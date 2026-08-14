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
        deps.audit_ks,
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
/// **Matched on the host's slot identifier (`mnemonic`), not the DID.** A slot
/// that was reserved but never published to has no DID at all, and it is
/// exactly as orphaned as one that was.
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
        deps.audit_ks,
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
        local_only = report.local_only.len(),
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
        HostOnlyDid, LocalOnlyDid, ReconcileWebvhServerDidsResultBody,
    };

    // Only records that claim to live on *this* server. `serverless` records
    // name no host, so they are not missing from one — they were never on it.
    let local: Vec<_> = all_local
        .iter()
        .filter(|r| r.server_id == server_key)
        .collect();

    let local_mnemonics: std::collections::HashSet<&str> =
        local.iter().map(|r| r.mnemonic.as_str()).collect();
    let host_mnemonics: std::collections::HashSet<&str> =
        hosted.iter().map(|e| e.mnemonic.as_str()).collect();

    let mut host_only: Vec<HostOnlyDid> = hosted
        .iter()
        .filter(|e| !local_mnemonics.contains(e.mnemonic.as_str()))
        .map(|e| HostOnlyDid {
            mnemonic: e.mnemonic.clone(),
            did: e.did_id.clone(),
            domain: e.domain.clone(),
            disabled: e.disabled,
        })
        .collect();
    let mut local_only: Vec<LocalOnlyDid> = local
        .iter()
        .filter(|r| !host_mnemonics.contains(r.mnemonic.as_str()))
        .map(|r| LocalOnlyDid {
            did: r.did.clone(),
            mnemonic: r.mnemonic.clone(),
            context_id: r.context_id.clone(),
        })
        .collect();
    // Stable order so two runs are diffable and a scripted check can compare
    // output between them.
    host_only.sort_by(|a, b| a.mnemonic.cmp(&b.mnemonic));
    local_only.sort_by(|a, b| a.mnemonic.cmp(&b.mnemonic));

    let in_both = u32::try_from(hosted.len().saturating_sub(host_only.len())).unwrap_or(u32::MAX);

    ReconcileWebvhServerDidsResultBody {
        server_id: server_label.to_string(),
        host_only,
        local_only,
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
        assert!(report.local_only.is_empty());
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
        assert_eq!(report.host_only[0].mnemonic, "attract-case");
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
        assert_eq!(report.local_only.len(), 1);
        assert_eq!(report.local_only[0].mnemonic, "never-landed");
        assert_eq!(report.local_only[0].context_id, "ctx");
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
        assert!(report.local_only.is_empty());
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
            .map(|e| e.mnemonic.as_str())
            .collect();
        assert_eq!(order, ["alpha", "mike", "zulu"]);
    }
}
