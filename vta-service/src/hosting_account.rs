//! This VTA's account on a DID hosting service it self-registered with
//! (`did-management/account/*`).
//!
//! A VTA that registered its own DID with a third-party host as a stranger
//! (setup's `[vta_did.hosting]`, `account/register/0.1`) holds that DID under
//! the domain's self-registration terms. Among them is an inactivity
//! lifecycle: an account that shows no activity is disabled — its DIDs answer
//! 404 — and, after a grace period, purged. This module keeps the account
//! alive and keeps what this VTA knows about it current:
//!
//! - **Renewal** (`account/renew/0.1`) at every start and about daily while
//!   running ([`spawn`]). Renewal is the liveness signal the host is told to
//!   expect, and the only thing that restores an account the lifecycle
//!   disabled.
//! - **The account as the host holds it** comes back with every renewal, so
//!   the boot renewal is also the boot status check. An expiry notice the host
//!   sent while this VTA was offline may have been dropped by its mediator, and
//!   the host never resends a stage once a transport took it: the host's
//!   answer, not the notice, is authoritative. `account/status/0.1` is kept
//!   for a passive look ([`refresh`] with `renew: false`), which by design
//!   keeps nothing alive.
//! - **Expiry notices** (`account/expiry-notice/0.1`) the host sends before it
//!   disables, when it disables, and before it purges ([`receive_notice`]).
//!   Kept only from the host this VTA registered with.
//!
//! Everything this VTA knows is one record in the `service_state` keyspace
//! ([`HostingAccountRecord`]). It travels with a backup, so a VTA restored
//! elsewhere (an embedded VTA exported to a hosted one) carries on renewing
//! the same account.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;

use crate::error::AppError;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

/// The `service_state` key the record is held under.
pub const RECORD_KEY: &str = "hosting_account";

/// How often a running VTA renews.
const RENEW_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a failed renewal waits before it is tried again, and the cap the
/// backoff doubles up to. Well inside the shortest inactivity period a host
/// would set (a day), so one outage never costs the account.
const RETRY_FIRST: Duration = Duration::from_secs(5 * 60);
const RETRY_MAX: Duration = Duration::from_secs(4 * 60 * 60);

/// What this VTA knows about its self-registered hosting account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostingAccountRecord {
    /// The id the host is registered under in this VTA's webvh server list.
    pub server_id: String,
    /// The host's DID: the only issuer an expiry notice is accepted from.
    pub server_did: String,
    /// The domain the account is on.
    pub domain: String,
    pub registered_at: DateTime<Utc>,
    /// The account as the host last reported it (`HostingAccount`, as JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Value>,
    /// When `account` was last read from the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    /// When the host last accepted a renewal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewed_at: Option<DateTime<Utc>>,
    /// The latest expiry notice the host sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_notice: Option<ExpiryNotice>,
    /// The last failure to reach the host, cleared by the next success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// One `account/expiry-notice/0.1` as received.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryNotice {
    /// `disablePending`, `disabled` or `purgePending`.
    pub stage: String,
    pub received_at: DateTime<Utc>,
}

impl HostingAccountRecord {
    /// A record for an account the host just opened.
    pub fn registered(
        server_id: &str,
        server_did: &str,
        domain: &str,
        account: Option<Value>,
    ) -> Self {
        let now = Utc::now();
        Self {
            server_id: server_id.into(),
            server_did: server_did.into(),
            domain: domain.into(),
            registered_at: now,
            checked_at: account.as_ref().map(|_| now),
            account,
            renewed_at: Some(now),
            last_notice: None,
            last_error: None,
        }
    }
}

/// The record, if this VTA self-registered with a host.
pub async fn load(ks: &KeyspaceHandle) -> Result<Option<HostingAccountRecord>, AppError> {
    ks.get(RECORD_KEY).await
}

pub async fn store(ks: &KeyspaceHandle, record: &HostingAccountRecord) -> Result<(), AppError> {
    ks.insert(RECORD_KEY, record).await
}

/// Renew the account (`renew: true`) or only read it (`renew: false`,
/// `account/status`, which counts as no activity), and record what the host
/// said. A failure is recorded on the record and returned.
pub async fn refresh(state: &AppState, renew: bool) -> Result<HostingAccountRecord, AppError> {
    let Some(mut record) = load(&state.service_state_ks).await? else {
        return Err(AppError::NotFound(
            "this VTA has no self-registered hosting account".into(),
        ));
    };
    let outcome = talk_to_host(state, &record, renew).await;
    let now = Utc::now();
    match outcome {
        Ok((account, renewed)) => {
            record.account = Some(account);
            record.checked_at = Some(now);
            if renewed {
                record.renewed_at = Some(now);
            }
            record.last_error = None;
            store(&state.service_state_ks, &record).await?;
            Ok(record)
        }
        Err(e) => {
            record.last_error = Some(e.to_string());
            store(&state.service_state_ks, &record).await?;
            Err(e)
        }
    }
}

async fn talk_to_host(
    state: &AppState,
    record: &HostingAccountRecord,
    renew: bool,
) -> Result<(Value, bool), AppError> {
    let resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .ok_or_else(|| AppError::Internal("no VTA DID configured".into()))?;
    let deps = crate::operations::did_webvh::WebvhDeps::from_app_state(state, resolver);
    let server = crate::webvh_store::get_server(&state.webvh_ks, &record.server_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "hosting server `{}` is no longer registered with this VTA",
                record.server_id
            ))
        })?;
    let client = crate::operations::did_webvh::host_client(&deps, &vta_did, &server).await?;

    // Renew returns the whole account, so a renewal never needs a status read
    // first; status is for a passive look that must not count as activity.
    if !renew {
        return Ok((serde_json::to_value(client.account_status().await?)?, false));
    }
    let (account, changed) = client.renew_account().await?;
    if changed {
        tracing::info!(
            server = %record.server_did,
            "hosting account restored by renewal"
        );
    }
    Ok((serde_json::to_value(account)?, true))
}

/// Keep the account alive for as long as the service runs: renew at
/// start, renew about daily, a failure retried with a bounded backoff.
/// Returns at once when this VTA holds no self-registered account.
pub fn spawn(state: AppState, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match load(&state.service_state_ks).await {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the hosting account record");
                return;
            }
        }
        let mut retry = RETRY_FIRST;
        loop {
            let wait = match refresh(&state, true).await {
                Ok(record) => {
                    retry = RETRY_FIRST;
                    let account_state = record
                        .account
                        .as_ref()
                        .and_then(|a| a.get("state"))
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    tracing::info!(
                        server = %record.server_did,
                        state = account_state,
                        "hosting account renewed"
                    );
                    RENEW_EVERY
                }
                // Purged (`noAccount`, or refused as the stranger a purge makes
                // it: `permissionDenied`) or held by an administrator
                // (`suspended`): renewing cannot change any of them, so stop
                // asking. The record keeps the error for whoever reads it.
                Err(AppError::NotFound(why) | AppError::Forbidden(why)) => {
                    tracing::error!(
                        reason = %why,
                        "the hosting account is gone or suspended; renewal cannot restore it — \
                         this VTA's DID may no longer be hosted"
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, retry_in = ?retry, "hosting account renewal failed");
                    let wait = retry;
                    retry = (retry * 2).min(RETRY_MAX);
                    wait
                }
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    })
}

/// Take an `account/expiry-notice/0.1` from `sender`: kept only when the
/// sender is the host this VTA registered with (compared as identities), and
/// then it updates the record. Answers nothing either way — the task is
/// one-way.
pub async fn receive_notice(
    state: &AppState,
    sender: &str,
    stage: &str,
    account: Value,
) -> Result<bool, AppError> {
    let Some(mut record) = load(&state.service_state_ks).await? else {
        return Ok(false);
    };
    if vta_sdk::did_scid::identity(sender) != vta_sdk::did_scid::identity(&record.server_did) {
        tracing::warn!(
            sender,
            host = %record.server_did,
            "dropped a hosting expiry notice from a party that is not this VTA's host"
        );
        return Ok(false);
    }
    let now = Utc::now();
    record.account = Some(account);
    record.checked_at = Some(now);
    record.last_notice = Some(ExpiryNotice {
        stage: stage.to_string(),
        received_at: now,
    });
    store(&state.service_state_ks, &record).await?;
    tracing::warn!(
        host = %record.server_did,
        stage,
        "hosting account expiry notice — renew, or this VTA's DID stops resolving"
    );
    Ok(true)
}
