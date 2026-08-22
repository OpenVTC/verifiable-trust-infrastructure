//! CRUD + DID validation for webvh hosting servers.
//!
//! The VTA maintains a registry of webvh servers that it can publish
//! `did.jsonl` logs to. Each entry is a `WebvhServerRecord` keyed by a
//! short operator-chosen id (`"prod"`, `"staging"`) pointing at the
//! server's DID. Resolution of the DID → transport endpoint is done
//! lazily at publish/fetch time by the `WebvhTransport` in the parent
//! module.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;
use vta_sdk::protocols::did_management::servers::{
    ListWebvhServersResultBody, RegisterWebvhServerResultBody, RemoveWebvhServerResultBody,
};
use vta_sdk::webvh::WebvhServerRecord;

/// Register a webvh host, or update the label of one already
/// registered — `spec/vta/webvh/servers/register/1.0`.
///
/// The `id` decides which happens; there is no mode flag. A new `id`
/// requires `did` and validates it over the network before storing. An
/// existing `id` updates the label only, and a `did` that differs from
/// the stored one is **refused**: re-pointing a registration silently
/// redirects every DID resolving through it, and unwinding that needs
/// coordinated teardown on the old host.
pub async fn register_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    server_did: Option<&str>,
    label: Option<String>,
    // Only needed to create a registration — the label-only path never
    // resolves anything, so a caller that is just relabelling may pass
    // `None` rather than having to construct a resolver.
    did_resolver: Option<&DIDCacheClient>,
    channel: &str,
) -> Result<RegisterWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    if let Some(mut record) = webvh_store::get_server(webvh_ks, id).await? {
        // Re-registering the same host is idempotent; pointing the same
        // id at a different host is not something this op will do.
        if let Some(did) = server_did
            && did != record.did
        {
            return Err(AppError::Conflict(format!(
                "webvh server {id} is registered to {}; re-pointing it at {did} would redirect                  every DID resolving through it. Remove the registration and add it again,                  after migrating those DIDs off the old host",
                record.did
            )));
        }

        if let Some(lbl) = label {
            record.label = if lbl.is_empty() { None } else { Some(lbl) };
        }
        record.updated_at = Utc::now();
        webvh_store::store_server(webvh_ks, &record).await?;

        info!(channel, id = %id, "webvh server updated");
        return Ok(record);
    }

    // No stored record and no `did` to create one with: the caller was
    // updating something that does not exist. NotFound (404), not a
    // validation error — this is what preserves `PATCH
    // /webvh/servers/{id}`'s contract now that it shares this op.
    let server_did = server_did.ok_or_else(|| {
        AppError::NotFound(format!(
            "webvh server not found: {id}; supply `did` to register it"
        ))
    })?;

    // Validate the DID resolves and has a supported WebVH service.
    let did_resolver =
        did_resolver.ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    validate_server_did(did_resolver, server_did).await?;

    let now = Utc::now();
    let record = WebvhServerRecord {
        id: id.to_string(),
        did: server_did.to_string(),
        label,
        created_at: now,
        updated_at: now,
    };
    webvh_store::store_server(webvh_ks, &record).await?;

    info!(channel, id = %id, did = %server_did, "webvh server added");
    Ok(record)
}

pub async fn list_webvh_servers(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    channel: &str,
) -> Result<ListWebvhServersResultBody, AppError> {
    // Any authenticated user can list servers
    let servers = webvh_store::list_servers(webvh_ks).await?;
    info!(channel, caller = %auth.did, count = servers.len(), "webvh servers listed");
    Ok(ListWebvhServersResultBody { servers })
}

/// Authenticate to the registered hosting server and relay its
/// `/api/me/domains` view to the caller. Used by
/// `pnm did-mgmt list-domains` and the interactive `--domain`
/// prompt in `create-did` / `register-did`.
///
/// Only the REST transport is supported today — the v0.8
/// `did-management/me/domains/...` task is REST-only on the
/// hosting server side. For DIDComm-only servers we return an
/// empty list and a `None` default so the CLI falls back to the
/// server-side resolution chain rather than blocking the user.
pub async fn list_webvh_server_domains(
    deps: &crate::operations::did_webvh::WebvhDeps<'_>,
    auth: &AuthClaims,
    vta_did: Option<&str>,
    server_id: &str,
) -> Result<vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsResultBody, AppError>
{
    use vta_sdk::protocols::did_management::servers::{
        ListWebvhServerDomainsResultBody, WebvhServerDomainEntry,
    };

    // Any authenticated caller may discover hosting domains —
    // identical scope rule as `list_webvh_servers`.
    let server = webvh_store::get_server(deps.webvh_ks, server_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

    let vta_did_value = vta_did.ok_or_else(|| {
        AppError::Validation(
            "VTA DID is not configured — complete `vta setup` before listing hosting domains."
                .to_string(),
        )
    })?;

    let identity = crate::operations::did_webvh::auth_cache::load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit,
        vta_did_value,
    )
    .await?;
    let auth_ctx = crate::operations::did_webvh::auth_cache::AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };

    let transport = crate::operations::did_webvh::WebvhTransport::from_server_authenticated(
        &server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;
    let entries = match transport {
        crate::operations::did_webvh::WebvhTransport::Rest(c) => {
            let resp = c.list_my_domains().await?;
            ListWebvhServerDomainsResultBody {
                domains: resp
                    .domains
                    .into_iter()
                    .map(|d| WebvhServerDomainEntry {
                        name: d.name,
                        default_domain: d.default_domain,
                        status: d.status,
                        label: d.label,
                        // The host speaks Unix seconds; the canonical
                        // DomainEntry speaks RFC 3339. An unrepresentable
                        // timestamp becomes absent rather than epoch-zero,
                        // which would read as "created in 1970".
                        created_at: d.created_at.and_then(|secs| {
                            chrono::DateTime::from_timestamp(secs as i64, 0)
                                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                        }),
                    })
                    .collect(),
                default: resp.default,
            }
        }
        crate::operations::did_webvh::WebvhTransport::DIDComm { .. } => {
            // DIDComm-only servers don't have a `me/domains` op
            // in the v0.8 surface; the CLI falls back to the
            // server's resolution chain.
            ListWebvhServerDomainsResultBody {
                domains: vec![],
                default: None,
            }
        }
    };
    info!(
        channel = "rest",
        caller = %auth.did,
        server_id = %server_id,
        count = entries.domains.len(),
        "webvh server hosting domains listed"
    );
    Ok(entries)
}

/// Compare what a hosting server holds for this VTA against what the VTA has
/// records for, and report the two divergences.
///
/// Read-only. It repairs nothing on purpose: the two sides need opposite
/// remedies — a host-only entry is a DID nobody can update any more and wants
/// removing from the host, a local-only entry may be a publish worth retrying —
/// and neither is safe to guess at from a list. Naming them is the whole job.
///
/// **Super-admin.** The host has no notion of VTA contexts, so its listing
/// cannot be filtered the way `list_dids_webvh` filters local records by
/// `has_context_access`. A context-scoped caller would see DIDs from contexts
/// they cannot act in — and scoping the *result* instead would hide orphans
/// from everyone, since an orphan has no local record and therefore no context
/// to check. So the operation is unrestricted-admin only, like the other
/// cross-context reads (`backup export`, `contexts create`).
///
/// **Matched on the host's slot identifier, not the DID.** A slot that was
/// reserved but never published to has no DID at all, and it is exactly as
/// orphaned as one that was.
///
/// That identifier is `mnemonic` in did-hosting's API and in
/// `WebvhDidRecord`, and `slotId` on the wire — the rename happens at the
/// boundary, in the `HostOnlyDid` / `AgentOnlyDid` construction below. The
/// spec (`vta/webvh/servers/reconcile/0.1`, dtgwg-trust-tasks-tf#210) uses
/// `slotId` because `mnemonic` already means a BIP-39 recovery phrase
/// everywhere else in these deployments, and a published wire contract should
/// not overload it.
pub async fn reconcile_webvh_server_dids(
    deps: &crate::operations::did_webvh::WebvhDeps<'_>,
    auth: &AuthClaims,
    vta_did: Option<&str>,
    server_id: &str,
) -> Result<vta_sdk::protocols::did_management::servers::ReconcileWebvhServerDidsResultBody, AppError>
{
    auth.require_super_admin()?;

    let server = webvh_store::get_server(deps.webvh_ks, server_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

    let vta_did_value = vta_did.ok_or_else(|| {
        AppError::Validation(
            "VTA DID is not configured — complete `vta setup` before reconciling with a host."
                .to_string(),
        )
    })?;

    let identity = crate::operations::did_webvh::auth_cache::load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit,
        vta_did_value,
    )
    .await?;
    let auth_ctx = crate::operations::did_webvh::auth_cache::AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };
    let transport = crate::operations::did_webvh::WebvhTransport::from_server_authenticated(
        &server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;

    let hosted = match transport {
        crate::operations::did_webvh::WebvhTransport::Rest(c) => {
            c.list_dids_for_owner(vta_did_value).await?
        }
        crate::operations::did_webvh::WebvhTransport::DIDComm { .. } => {
            // Refuse rather than answer "nothing to report". `/api/dids` is
            // REST-only on the host, and an empty diff here would read as
            // "checked, all clean" — the one wrong answer this operation can
            // give, because it is the answer an operator stops looking after.
            return Err(AppError::Validation(format!(
                "server `{server_id}` is reachable over DIDComm only, and the host's DID \
                 listing is REST-only — this VTA cannot reconcile against it. Register a \
                 REST endpoint for the server to use this command."
            )));
        }
    };

    let all_local = webvh_store::list_dids(deps.webvh_ks).await?;
    let report = diff_host_against_local(&hosted, &all_local, &server.id, server_id);

    info!(
        caller = %auth.did,
        server_id = %server_id,
        host_only = report.host_only.len(),
        agent_only = report.agent_only.len(),
        in_both = report.in_both,
        "webvh server DIDs reconciled"
    );

    Ok(report)
}

/// The comparison itself, with the I/O lifted out so it can be tested.
///
/// `server_key` is the record's `server_id` (what the local side is filtered
/// by); `server_label` is what goes in the report. They are the same value in
/// practice — separate parameters only so the filter cannot silently read the
/// caller's raw argument instead of the resolved server's id.
fn diff_host_against_local(
    hosted: &[crate::webvh_client::HostedDidEntry],
    all_local: &[vta_sdk::webvh::WebvhDidRecord],
    server_key: &str,
    server_label: &str,
) -> vta_sdk::protocols::did_management::servers::ReconcileWebvhServerDidsResultBody {
    use vta_sdk::protocols::did_management::servers::{
        AgentOnlyDid, HostOnlyDid, ReconcileWebvhServerDidsResultBody,
    };

    // Only records that claim to live on *this* server. `serverless` records
    // name no host, so they are not missing from one — they were never on it.
    let local: Vec<_> = all_local
        .iter()
        .filter(|r| r.server_id == server_key)
        .collect();

    // Both sides key on the host's slot identifier, which each end spells
    // `mnemonic` in its own type (`WebvhDidRecord`, `HostedDidEntry`); it
    // becomes `slotId` only on the wire.
    let local_slots: std::collections::HashSet<&str> =
        local.iter().map(|r| r.mnemonic.as_str()).collect();
    let host_slots: std::collections::HashSet<&str> =
        hosted.iter().map(|e| e.mnemonic.as_str()).collect();

    let mut host_only: Vec<HostOnlyDid> = hosted
        .iter()
        .filter(|e| !local_slots.contains(e.mnemonic.as_str()))
        .map(|e| HostOnlyDid {
            slot_id: e.mnemonic.clone(),
            did: e.did_id.clone(),
            domain: e.domain.clone(),
            disabled: e.disabled,
        })
        .collect();
    let mut agent_only: Vec<AgentOnlyDid> = local
        .iter()
        .filter(|r| !host_slots.contains(r.mnemonic.as_str()))
        .map(|r| AgentOnlyDid {
            did: r.did.clone(),
            slot_id: r.mnemonic.clone(),
            context_id: r.context_id.clone(),
        })
        .collect();
    // Stable order so two runs are diffable and a scripted check can compare
    // output between them.
    host_only.sort_by(|a, b| a.slot_id.cmp(&b.slot_id));
    agent_only.sort_by(|a, b| a.slot_id.cmp(&b.slot_id));

    let in_both = u32::try_from(hosted.len().saturating_sub(host_only.len())).unwrap_or(u32::MAX);

    ReconcileWebvhServerDidsResultBody {
        server_id: server_label.to_string(),
        host_only,
        agent_only,
        in_both,
    }
}

pub async fn remove_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<RemoveWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    webvh_store::get_server(webvh_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {id}")))?;

    webvh_store::delete_server(webvh_ks, id).await?;

    info!(channel, id = %id, "webvh server removed");
    Ok(RemoveWebvhServerResultBody {
        id: id.to_string(),
        removed: true,
    })
}

/// Validate that a DID resolves and has at least one supported WebVH service.
///
/// Accepts any of the types listed in
/// [`super::transport::SUPPORTED_TYPES_HUMAN`]. Delegates to
/// [`super::transport::resolve_server_transport`] so the accepted-types
/// set is defined in exactly one place — adding or removing a type
/// changes both validation and runtime selection together.
pub(super) async fn validate_server_did(
    did_resolver: &DIDCacheClient,
    server_did: &str,
) -> Result<(), AppError> {
    let resolved = did_resolver.resolve(server_did).await.map_err(|e| {
        AppError::Validation(format!("failed to resolve server DID {server_did}: {e}"))
    })?;

    if super::transport::resolve_server_transport(&resolved.doc.service).is_none() {
        return Err(AppError::Validation(format!(
            "server DID {server_did} has no supported webvh endpoint (expected: {})",
            super::transport::SUPPORTED_TYPES_HUMAN,
        )));
    }

    Ok(())
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;
    use crate::webvh_client::HostedDidEntry;
    use vta_sdk::webvh::WebvhDidRecord;

    fn hosted(mnemonic: &str, did: Option<&str>) -> HostedDidEntry {
        HostedDidEntry {
            mnemonic: mnemonic.into(),
            did_id: did.map(str::to_string),
            domain: Some("webvh.example".into()),
            disabled: false,
            updated_at: 0,
        }
    }

    fn local(mnemonic: &str, server_id: &str) -> WebvhDidRecord {
        WebvhDidRecord {
            did: format!("did:webvh:QmScid:webvh.example:{mnemonic}"),
            server_id: server_id.into(),
            mnemonic: mnemonic.into(),
            scid: "QmScid".into(),
            context_id: "ctx".into(),
            portable: false,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 2,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn agreement_reports_a_count_and_no_divergence() {
        let report = diff_host_against_local(
            &[hosted(
                "alpha",
                Some("did:webvh:QmScid:webvh.example:alpha"),
            )],
            &[local("alpha", "prod")],
            "prod",
            "prod",
        );
        assert!(report.host_only.is_empty());
        assert!(report.agent_only.is_empty());
        // Counted, not merely silent — "nothing to report" and "the listing
        // failed" have to look different to the operator.
        assert_eq!(report.in_both, 1);
    }

    /// The case this command exists for: the host serves a DID the VTA deleted.
    #[test]
    fn a_did_the_host_has_and_the_vta_does_not_is_an_orphan() {
        let report = diff_host_against_local(
            &[hosted(
                "attract-case",
                Some("did:webvh:Qmc33:webvh.example:attract-case"),
            )],
            &[],
            "prod",
            "prod",
        );
        assert_eq!(report.host_only.len(), 1);
        assert_eq!(report.host_only[0].slot_id, "attract-case");
        assert_eq!(
            report.host_only[0].did.as_deref(),
            Some("did:webvh:Qmc33:webvh.example:attract-case")
        );
        assert_eq!(report.in_both, 0);
    }

    /// A slot reserved but never published to has no DID at all — and is
    /// exactly as orphaned as one that was. Matching on the DID instead of the
    /// host's slot identifier would drop these silently.
    #[test]
    fn a_never_published_slot_is_still_an_orphan() {
        let report = diff_host_against_local(&[hosted("reserved", None)], &[], "prod", "prod");
        assert_eq!(report.host_only.len(), 1);
        assert!(report.host_only[0].did.is_none());
    }

    #[test]
    fn a_did_the_vta_has_and_the_host_does_not_is_reported_the_other_way() {
        let report = diff_host_against_local(&[], &[local("never-landed", "prod")], "prod", "prod");
        assert_eq!(report.agent_only.len(), 1);
        assert_eq!(report.agent_only[0].slot_id, "never-landed");
        assert_eq!(report.agent_only[0].context_id, "ctx");
        assert!(report.host_only.is_empty());
    }

    /// Records belonging to another server — or to no server — are not missing
    /// from this one. Without the filter every serverless DID would be reported
    /// as absent from a host it was never on, which is the kind of false alarm
    /// that gets a diagnostic ignored.
    #[test]
    fn records_for_other_servers_are_not_reported_as_missing() {
        let report = diff_host_against_local(
            &[],
            &[
                local("elsewhere", "staging"),
                local("local-only-did", "serverless"),
            ],
            "prod",
            "prod",
        );
        assert!(report.agent_only.is_empty());
        assert!(report.host_only.is_empty());
        assert_eq!(report.in_both, 0);
    }

    #[test]
    fn output_order_is_stable_regardless_of_listing_order() {
        let report = diff_host_against_local(
            &[
                hosted("zulu", None),
                hosted("alpha", None),
                hosted("mike", None),
            ],
            &[],
            "prod",
            "prod",
        );
        let order: Vec<&str> = report
            .host_only
            .iter()
            .map(|e| e.slot_id.as_str())
            .collect();
        assert_eq!(order, ["alpha", "mike", "zulu"]);
    }
}

/// Why a retire-orphan request was refused.
///
/// Separate from [`AppError`] because each variant carries the extended error
/// code its specification defines (`vta/webvh/servers/retire-orphan:*`), and
/// the caller keys on that rather than on prose. Two of the three are
/// *uncertainty* rather than contradiction — the VTA does not know the slot is
/// safe to remove — and refusing on uncertainty is the whole point: the
/// alternative to a false refusal is a retry, and the alternative to a false
/// removal is nothing.
#[derive(Debug)]
pub enum RetireOrphanRefusal {
    /// The VTA holds a record for this slot, so it is not an orphan.
    NotOrphaned {
        slot_id: String,
        did: Option<String>,
    },
    /// The slot does not serve the DID the caller named — the report they
    /// acted on is stale.
    DidMismatch {
        slot_id: String,
        expected: String,
        actual: Option<String>,
    },
    /// Orphanhood could not be confirmed, so the VTA will not act on the
    /// caller's word for it.
    ListingUnavailable { server_id: String, detail: String },
}

impl RetireOrphanRefusal {
    /// The specification's extended code, for `details.reason`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotOrphaned { .. } => "vta/webvh/servers/retire-orphan:notOrphaned",
            Self::DidMismatch { .. } => "vta/webvh/servers/retire-orphan:didMismatch",
            Self::ListingUnavailable { .. } => "vta/webvh/servers/retire-orphan:listingUnavailable",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::NotOrphaned { slot_id, .. } => format!(
                "slot `{slot_id}` has a record in this VTA, so it is not an orphan. \
                 retire-orphan applies only to slots this VTA has no record of — \
                 use `webvh/dids/delete` for one it still controls."
            ),
            Self::DidMismatch {
                slot_id, actual, ..
            } => format!(
                "slot `{slot_id}` serves {} — not the DID named. Re-run reconcile \
                 before retiring it.",
                actual.as_deref().unwrap_or("no DID")
            ),
            Self::ListingUnavailable { server_id, detail } => format!(
                "cannot confirm slot orphanhood on server `{server_id}`: {detail}. \
                 Refusing rather than removing on the caller's word."
            ),
        }
    }
}

/// Whether this slot may be retired, and what would go — with the I/O lifted
/// out so every refusal is testable without a host.
///
/// This is the safety property in one function. A slot absent from `host_only`
/// is either unknown to the host or known to us; both mean retire-orphan is the
/// wrong instrument, and the local record is what tells them apart in the
/// message. The caller's request is never evidence of orphanhood — only this
/// comparison is.
///
/// Returns the DID that would stop resolving and the host domain to address, so
/// the caller has both without re-searching the report.
#[allow(clippy::type_complexity)]
fn decide_retirement(
    report: &vta_sdk::protocols::did_management::servers::ReconcileWebvhServerDidsResultBody,
    all_local: &[vta_sdk::webvh::WebvhDidRecord],
    server_key: &str,
    slot_id: &str,
    expected_did: Option<&str>,
) -> Result<(Option<String>, Option<String>), RetireOrphanRefusal> {
    let Some(orphan) = report.host_only.iter().find(|h| h.slot_id == slot_id) else {
        let local = all_local
            .iter()
            .find(|r| r.mnemonic == slot_id && r.server_id == server_key);
        return Err(RetireOrphanRefusal::NotOrphaned {
            slot_id: slot_id.to_string(),
            did: local.map(|r| r.did.clone()),
        });
    };

    // Optimistic concurrency against a stale report: a reconcile response is a
    // comparison at an instant, so naming what was seen turns a slot published
    // to in the meantime into a refusal rather than a surprise.
    if let Some(expected) = expected_did
        && orphan.did.as_deref() != Some(expected)
    {
        return Err(RetireOrphanRefusal::DidMismatch {
            slot_id: slot_id.to_string(),
            expected: expected.to_string(),
            actual: orphan.did.clone(),
        });
    }

    Ok((orphan.did.clone(), orphan.domain.clone()))
}

/// Retire an orphaned slot on a hosting server.
///
/// Implements `vta/webvh/servers/retire-orphan/0.1`. See
/// [`reconcile_webvh_server_dids`] for how the orphan set is derived — this
/// re-derives it the same way rather than trusting the caller, which is the
/// property the whole operation rests on.
///
/// # Why the caller cannot simply be believed
///
/// A slot id is a bare string. If this trusted it, the operation would be
/// "delete anything on the host, unaudited by the VTA's own state" wearing a
/// narrower name. Re-deriving means a live DID is refused automatically,
/// because a live DID has a local record and that record is the refusal.
///
/// # Not automatic
///
/// Nothing in this service calls it on a timer or as a consequence of another
/// task, and nothing should. The signal it acts on is an *absence*, and
/// absences are produced by bugs as readily as by orphaning — a storage read
/// that fails open, a record written under the wrong server id. Each of those
/// presents as an orphan, and the response would be to make a published
/// identifier stop resolving, irreversibly.
pub async fn retire_orphan_slot(
    deps: &crate::operations::did_webvh::WebvhDeps<'_>,
    auth: &AuthClaims,
    vta_did: Option<&str>,
    body: &vta_sdk::protocols::did_management::servers::RetireOrphanSlotBody,
) -> Result<
    Result<
        vta_sdk::protocols::did_management::servers::RetireOrphanSlotResultBody,
        RetireOrphanRefusal,
    >,
    AppError,
> {
    use vta_sdk::protocols::did_management::servers::RetireOrphanSlotResultBody;

    // At least as broad as reconcile demands. A slot absent from this VTA
    // belongs to no context here, so there is no scope to narrow to — and this
    // one writes.
    auth.require_super_admin()?;

    let server = webvh_store::get_server(deps.webvh_ks, &body.server_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {}", body.server_id)))?;

    let vta_did_value = vta_did.ok_or_else(|| {
        AppError::Validation(
            "VTA DID is not configured — complete `vta setup` before retiring a slot.".to_string(),
        )
    })?;

    let identity = crate::operations::did_webvh::auth_cache::load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit,
        vta_did_value,
    )
    .await?;
    let auth_ctx = crate::operations::did_webvh::auth_cache::AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };
    let transport = crate::operations::did_webvh::WebvhTransport::from_server_authenticated(
        &server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;

    let client = match transport {
        crate::operations::did_webvh::WebvhTransport::Rest(c) => c,
        crate::operations::did_webvh::WebvhTransport::DIDComm { .. } => {
            // Same refusal reconcile gives, and for the same reason: the
            // listing is REST-only, and without it orphanhood is unproven.
            return Ok(Err(RetireOrphanRefusal::ListingUnavailable {
                server_id: body.server_id.clone(),
                detail: "the host's DID listing is REST-only and this server is \
                         registered over DIDComm"
                    .to_string(),
            }));
        }
    };

    let hosted = match client.list_dids_for_owner(vta_did_value).await {
        Ok(h) => h,
        Err(e) => {
            return Ok(Err(RetireOrphanRefusal::ListingUnavailable {
                server_id: body.server_id.clone(),
                detail: e.to_string(),
            }));
        }
    };
    let all_local = webvh_store::list_dids(deps.webvh_ks).await?;
    let report = diff_host_against_local(&hosted, &all_local, &server.id, &body.server_id);

    let (retired_did, domain) = match decide_retirement(
        &report,
        &all_local,
        &server.id,
        &body.slot_id,
        body.expected_did.as_deref(),
    ) {
        Ok(t) => t,
        Err(refusal) => return Ok(Err(refusal)),
    };
    client
        .delete_did(&body.slot_id, domain.as_deref())
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "host refused to retire slot `{}`: {e}",
                body.slot_id
            ))
        })?;

    // Transport literal rather than the const: `trust_tasks::webvh` is private
    // to the dispatcher, and an operation should not reach into it.
    // The slot will not exist to be asked about afterwards, so this row is the
    // only account of what happened — including why, when the operator said.
    crate::audit::record_with_detail(
        deps.audit,
        "webvh.slot.retire_orphan",
        &auth.did,
        Some(&body.slot_id),
        "success",
        Some("trust-task"),
        None,
        body.reason.as_deref(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "retire-orphan audit record failed");
    });

    info!(
        caller = %auth.did,
        server_id = %body.server_id,
        slot_id = %body.slot_id,
        did = retired_did.as_deref().unwrap_or("<unpublished>"),
        "orphaned webvh slot retired"
    );

    Ok(Ok(RetireOrphanSlotResultBody {
        server_id: body.server_id.clone(),
        slot_id: body.slot_id.clone(),
        retired: true,
        did: retired_did,
    }))
}

#[cfg(test)]
mod retire_orphan_tests {
    use super::*;
    use crate::webvh_client::HostedDidEntry;
    use vta_sdk::webvh::WebvhDidRecord;

    const SERVER: &str = "primary-host";

    fn hosted(mnemonic: &str, did: Option<&str>) -> HostedDidEntry {
        HostedDidEntry {
            mnemonic: mnemonic.into(),
            did_id: did.map(str::to_string),
            domain: Some("webvh.example".into()),
            disabled: false,
            updated_at: 0,
        }
    }

    fn local(mnemonic: &str) -> WebvhDidRecord {
        WebvhDidRecord {
            did: format!("did:webvh:QmScid:webvh.example:{mnemonic}"),
            server_id: SERVER.into(),
            mnemonic: mnemonic.into(),
            scid: "QmScid".into(),
            context_id: "ctx".into(),
            portable: false,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 2,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn decide(
        hosted_slots: &[HostedDidEntry],
        local_records: &[WebvhDidRecord],
        slot: &str,
        expected: Option<&str>,
    ) -> Result<(Option<String>, Option<String>), RetireOrphanRefusal> {
        let report = diff_host_against_local(hosted_slots, local_records, SERVER, SERVER);
        decide_retirement(&report, local_records, SERVER, slot, expected)
    }

    /// The happy path: the host serves it, we have no record, so it goes.
    #[test]
    fn an_orphan_is_retirable_and_names_what_would_go() {
        let did = "did:webvh:QmScid:webvh.example:orphan";
        let (retired, domain) = decide(&[hosted("orphan", Some(did))], &[], "orphan", None)
            .expect("an orphan is retirable");
        assert_eq!(retired.as_deref(), Some(did));
        assert_eq!(domain.as_deref(), Some("webvh.example"));
    }

    /// A slot reserved but never published to is exactly as orphaned, and has
    /// no DID to name — which is why the operation keys on the slot.
    #[test]
    fn an_unpublished_slot_is_still_an_orphan() {
        let (retired, _) =
            decide(&[hosted("reserved", None)], &[], "reserved", None).expect("still an orphan");
        assert_eq!(retired, None);
    }

    /// The property everything rests on: a live DID has a local record, and
    /// that record is what makes the refusal automatic. A caller cannot
    /// retire it by naming it.
    #[test]
    fn a_slot_we_hold_a_record_for_is_refused() {
        let did = "did:webvh:QmScid:webvh.example:live";
        let refusal = decide(&[hosted("live", Some(did))], &[local("live")], "live", None)
            .expect_err("a live DID must be refused");
        assert!(
            refusal.code().ends_with(":notOrphaned"),
            "the extended code is what a caller keys on"
        );
        match &refusal {
            RetireOrphanRefusal::NotOrphaned { slot_id, did: d } => {
                assert_eq!(slot_id, "live");
                assert_eq!(
                    d.as_deref(),
                    Some(did),
                    "the refusal should name what it found, so the operator can see why"
                );
            }
            other => panic!("expected NotOrphaned, got {other:?}"),
        }
    }

    /// A slot the host does not serve is not an orphan either — there is
    /// nothing there to retire, and saying "retired" would be a lie.
    #[test]
    fn a_slot_the_host_does_not_serve_is_refused() {
        let refusal =
            decide(&[], &[], "ghost", None).expect_err("nothing to retire is not a success");
        assert!(matches!(refusal, RetireOrphanRefusal::NotOrphaned { .. }));
    }

    /// A report can go stale between being read and being acted on. Naming the
    /// DID that was seen is what turns that into a refusal.
    #[test]
    fn a_stale_report_is_refused_rather_than_retiring_the_wrong_thing() {
        let now_serves = "did:webvh:QmScid:webvh.example:published-since";
        let refusal = decide(
            &[hosted("attract-case", Some(now_serves))],
            &[],
            "attract-case",
            Some("did:webvh:QmScid:webvh.example:what-the-operator-saw"),
        )
        .expect_err("a mismatched DID must refuse");
        match refusal {
            RetireOrphanRefusal::DidMismatch { actual, .. } => {
                assert_eq!(actual.as_deref(), Some(now_serves));
            }
            other => panic!("expected DidMismatch, got {other:?}"),
        }
    }

    /// The guard also fires the other way: a slot that has since been published
    /// to, when the operator saw no DID at all.
    #[test]
    fn expecting_a_did_on_a_slot_that_has_none_is_refused() {
        let refusal = decide(
            &[hosted("reserved", None)],
            &[],
            "reserved",
            Some("did:webvh:QmScid:webvh.example:reserved"),
        )
        .expect_err("expected-vs-none must refuse");
        assert!(matches!(refusal, RetireOrphanRefusal::DidMismatch { .. }));
    }

    /// Omitting `expectedDid` skips the staleness guard — the caller has
    /// accepted that risk, and the orphanhood check still stands.
    #[test]
    fn omitting_the_expected_did_skips_only_the_staleness_guard() {
        let did = "did:webvh:QmScid:webvh.example:whatever";
        assert!(decide(&[hosted("slot", Some(did))], &[], "slot", None).is_ok());
        // …but not the orphanhood one.
        assert!(decide(&[hosted("slot", Some(did))], &[local("slot")], "slot", None).is_err());
    }

    /// A record naming a *different* server does not make this slot ours. The
    /// reconcile filter already scopes by server; this pins that the refusal
    /// path uses the same scoping rather than a global search.
    #[test]
    fn a_record_on_another_server_does_not_shield_the_slot() {
        let did = "did:webvh:QmScid:webvh.example:shared-name";
        let mut elsewhere = local("shared-name");
        elsewhere.server_id = "some-other-host".into();
        assert!(
            decide(
                &[hosted("shared-name", Some(did))],
                &[elsewhere],
                "shared-name",
                None
            )
            .is_ok(),
            "a slot recorded against another server is still an orphan on this one"
        );
    }

    /// Each refusal carries the code its specification defines; a caller keys
    /// on that rather than on prose, so the mapping is pinned.
    #[test]
    fn every_refusal_carries_its_specified_code() {
        let cases = [
            (
                RetireOrphanRefusal::NotOrphaned {
                    slot_id: "s".into(),
                    did: None,
                },
                "vta/webvh/servers/retire-orphan:notOrphaned",
            ),
            (
                RetireOrphanRefusal::DidMismatch {
                    slot_id: "s".into(),
                    expected: "did:webvh:a".into(),
                    actual: None,
                },
                "vta/webvh/servers/retire-orphan:didMismatch",
            ),
            (
                RetireOrphanRefusal::ListingUnavailable {
                    server_id: "s".into(),
                    detail: "down".into(),
                },
                "vta/webvh/servers/retire-orphan:listingUnavailable",
            ),
        ];
        for (refusal, code) in cases {
            assert_eq!(refusal.code(), code);
            assert!(
                !refusal.message().is_empty(),
                "{code} must explain itself to an operator"
            );
        }
    }
}
