//! The community badges, as ones the community issues, projected to its trust registry
//! (VTI-BDG-080).
//!
//! Each active community badge is published as one TRQP authorization record under the
//! community's authority: `{entity: the community's DID, authority: the community's DID,
//! action: "issue", resource: the badge's Achievement id}` — the very identifier the badge
//! credential's achievement carries, so an outside verifier asks the registry whether the
//! community issues that badge, and asks the community's status set whether the award
//! still stands. The community is the credential's issuer (VTI-BDG-060), so the record
//! names it; a record naming a badge group's DID, from before, is withdrawn as one no
//! longer wanted. The record's `context` marks it as a badge record and
//! names the badge by identifier only, never by name: a badge kept inside the community is
//! not described to the world (VTI-BDG-050).
//!
//! The VTC's own records stay the source of truth and the registry a projection of them,
//! as the capability modules and the git-namespace rights are. A [`Projector`] — the one
//! retry owner — publishes what is missing or changed and deletes what is no longer wanted
//! (a retired badge's record goes: VTI-BDG-080), keeping a mirror of what the registry
//! accepted (`breg:<key>` in the `badges` keyspace). Every [`VERIFY_SECONDS`] it compares
//! the mirror with the badge records the registry itself holds, where the registry can
//! enumerate them, and corrects either side. A badge change [`kick`]s it; otherwise it runs
//! on its tick.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::sync::{Notify, watch};
use tracing::{info, warn};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{BadgeKind, BadgeState};
use crate::registry::{RegistryError, TrustRegistryClient};
use crate::server::AppState;

/// The TRQP action the community publishes for each of its badges.
pub const ACTION: &str = "issue";
/// The `context.kind` that marks a record as this projection's, so it never touches the
/// community's other `issue` records.
pub const KIND: &str = "vtcBadgeIssuer";

const TICK_SECONDS: u64 = 60;
/// How often the projection is checked against what the registry itself holds.
pub const VERIFY_SECONDS: i64 = 900;

static KICK: Notify = Notify::const_new();

/// Ask the projector to run soon: a badge was defined, promoted or retired.
pub fn kick() {
    KICK.notify_one();
}

/// One record the registry should hold.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRecord {
    pub entity: String,
    pub resource: String,
    pub badge_id: String,
}

impl IssuerRecord {
    pub fn key(&self) -> String {
        format!("{}|{ACTION}|{}", self.entity, self.resource)
    }

    /// The TRQP `TrustRecord` for `registry/record/put`.
    pub fn record(&self, authority: &str) -> Value {
        json!({
            "entity_id": self.entity,
            "authority_id": authority,
            "action": ACTION,
            "resource": self.resource,
            "record_type": "authorization",
            "authorized": true,
            "context": { "kind": KIND, "badgeId": self.badge_id },
        })
    }

    /// Read one of this projection's records back from the registry's own answer, in
    /// either casing; `None` for any record that is not a badge issuer's.
    pub fn from_registry(r: &Value) -> Option<Self> {
        let field = |a: &str, b: &str| {
            r.get(a)
                .or_else(|| r.get(b))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        if field("action", "action")?.as_str() != ACTION {
            return None;
        }
        let context = r.get("context")?;
        if context.get("kind").and_then(Value::as_str) != Some(KIND) {
            return None;
        }
        Some(Self {
            entity: field("entityId", "entity_id")?,
            resource: field("resource", "resource")?,
            badge_id: context.get("badgeId")?.as_str()?.to_string(),
        })
    }
}

/// What the registry should hold now: one record per active community badge whose group
/// exists, keyed as the registry keys it.
pub async fn desired(state: &AppState) -> Result<BTreeMap<String, IssuerRecord>, AppError> {
    let (public_url, community_did) = {
        let config = state.config.read().await;
        (config.public_url.clone(), config.vtc_did.clone())
    };
    let Some(community_did) = community_did else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for badge in super::all_badges(&state.badges_ks).await? {
        if badge.kind != BadgeKind::Community || badge.state != BadgeState::Active {
            continue;
        }
        let Some(gid) = &badge.group_id else {
            continue;
        };
        if crate::groups::get(state.directory.ks(), gid)
            .await?
            .is_none()
        {
            continue;
        }
        let r = IssuerRecord {
            entity: community_did.clone(),
            resource: super::credential::achievement_id(&badge, public_url.as_deref()),
            badge_id: badge.badge_id.clone(),
        };
        out.insert(r.key(), r);
    }
    Ok(out)
}

fn mirror_key(key: &str) -> Vec<u8> {
    format!("breg:{key}").into_bytes()
}

/// What the registry accepted, as this VTC last saw it.
pub async fn published(ks: &KeyspaceHandle) -> Result<BTreeMap<String, IssuerRecord>, AppError> {
    let mut out = BTreeMap::new();
    for (key, raw) in ks.prefix_iter_raw(b"breg:".to_vec()).await? {
        if let Ok(r) = serde_json::from_slice::<IssuerRecord>(&raw) {
            out.insert(String::from_utf8_lossy(&key[5..]).to_string(), r);
        }
    }
    Ok(out)
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassReport {
    pub put: usize,
    pub deleted: usize,
    pub failed: usize,
}

/// Bring the registry to [`desired`]: publish what the mirror lacks, delete what the
/// mirror holds and nobody wants. A record the registry refused stays out of the mirror,
/// so the next pass tries it again.
pub async fn reconcile(
    state: &AppState,
    client: &dyn TrustRegistryClient,
    authority: &str,
) -> Result<PassReport, AppError> {
    let want = desired(state).await?;
    let have = published(&state.badges_ks).await?;
    let mut report = PassReport::default();
    for (key, r) in &want {
        if have.get(key) == Some(r) {
            continue;
        }
        match client.put_trust_record(&r.record(authority)).await {
            Ok(()) => {
                state.badges_ks.insert(mirror_key(key), r).await?;
                report.put += 1;
            }
            Err(e) => {
                report.failed += 1;
                warn!(badge = %r.badge_id, error = %e, "could not publish a badge group to the trust registry; retrying on the next pass");
            }
        }
    }
    for (key, r) in &have {
        if want.contains_key(key) {
            continue;
        }
        match client
            .delete_trust_record(&r.entity, ACTION, &r.resource)
            .await
        {
            Ok(()) => {
                state.badges_ks.remove(mirror_key(key)).await?;
                report.deleted += 1;
            }
            Err(e) => {
                report.failed += 1;
                warn!(badge = %r.badge_id, error = %e, "could not remove a retired badge group from the trust registry; retrying on the next pass");
            }
        }
    }
    Ok(report)
}

/// Check the mirror against the badge records the registry itself holds: one the registry
/// lost leaves the mirror (so [`reconcile`] publishes it again), and one it holds that is
/// not wanted — written before a crash cleared the mirror, say — is deleted. `Ok(false)`
/// when the registry cannot enumerate its records, and nothing was checked.
pub async fn verify(state: &AppState, client: &dyn TrustRegistryClient) -> Result<bool, AppError> {
    let held: BTreeMap<String, IssuerRecord> = match client.list_trust_records(ACTION).await {
        Ok(records) => records
            .iter()
            .filter_map(IssuerRecord::from_registry)
            .map(|r| (r.key(), r))
            .collect(),
        Err(RegistryError::Permanent(why)) => {
            tracing::debug!(%why, "the trust registry cannot enumerate badge issuer records");
            return Ok(false);
        }
        Err(e) => {
            warn!(error = %e, "could not read the trust registry's badge issuer records");
            return Ok(false);
        }
    };
    let want = desired(state).await?;
    let have = published(&state.badges_ks).await?;
    for key in have.keys() {
        if !held.contains_key(key) {
            state.badges_ks.remove(mirror_key(key)).await?;
        }
    }
    for (key, r) in &held {
        if !want.contains_key(key) && !have.contains_key(key) {
            // Unknown to the mirror and unwanted: let reconcile delete it.
            state.badges_ks.insert(mirror_key(key), r).await?;
        }
    }
    Ok(true)
}

/// The supervised loop.
pub struct Projector {
    state: AppState,
    client: Arc<dyn TrustRegistryClient>,
    authority: String,
    last_verify: Option<DateTime<Utc>>,
}

impl Projector {
    pub fn new(state: AppState, client: Arc<dyn TrustRegistryClient>, authority: String) -> Self {
        Self {
            state,
            client,
            authority,
            last_verify: None,
        }
    }

    /// One pass: a verify when one is due, then a reconcile. Errors are logged.
    pub async fn run_once(&mut self) {
        let now = Utc::now();
        if self
            .last_verify
            .is_none_or(|l| l + chrono::Duration::seconds(VERIFY_SECONDS) <= now)
        {
            self.last_verify = Some(now);
            if let Err(e) = verify(&self.state, self.client.as_ref()).await {
                warn!(error = %e, "badge issuer registry verify failed");
            }
        }
        match reconcile(&self.state, self.client.as_ref(), &self.authority).await {
            Ok(r) if r != PassReport::default() => info!(
                put = r.put,
                deleted = r.deleted,
                failed = r.failed,
                "badge issuer registry projection pass"
            ),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "badge issuer registry projection failed"),
        }
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!("badge issuer registry projector starting");
        let mut tick = tokio::time::interval(Duration::from_secs(TICK_SECONDS));
        loop {
            tokio::select! {
                _ = tick.tick() => self.run_once().await,
                _ = KICK.notified() => self.run_once().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("badge issuer registry projector stopping");
                        return;
                    }
                }
            }
        }
    }
}
