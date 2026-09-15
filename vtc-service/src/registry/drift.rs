//! Comparison of the local registry mirror against the trust registry itself.
//!
//! The `registry_records` keyspace has always held what this community believes
//! it published — [`RegistryRecord::for_job`] writes a row every time a sync job
//! succeeds, and [`super::model::RegistryRecord`]'s own doc comment says it
//! exists "so the daemon can detect drift at boot". Nothing ever detected any.
//! The mirror was written and never read, and `list_records` had no caller in
//! the service.
//!
//! This module is that missing half. It answers one question an operator cannot
//! otherwise ask: **is what we think we published actually there?**
//!
//! ## Why it is a background task and not a request handler
//!
//! Enumerating the registry is a network round trip, potentially several for a
//! paginated graph. The diagnostics surface it reports through is polled every
//! 15 seconds by the admin console, so computing on demand would turn one
//! operator with a browser tab open into a steady query load on a third party.
//! The check runs on its own timer and publishes a snapshot, exactly as the
//! health probe does.
//!
//! ## Why the answer is three-valued
//!
//! A disagreement is not automatically a fault, and the direction matters:
//!
//! - [`Disagreement::MissingAtRegistry`] — we hold a record the registry does
//!   not. A write was lost. This is the one that matters, and the one that was
//!   invisible: it is what a failed `publishMember` leaves behind.
//! - [`Disagreement::UnknownLocally`] — the registry holds a record we do not.
//!   Often benign (a record published by an earlier deployment, or by another
//!   admin), so it is reported without alarm.
//! - [`Disagreement::StatusMismatch`] — both hold the record and disagree on
//!   whether the member is active. A removal that half-landed.
//!
//! Collapsing these into a count would lose the only thing that tells an
//! operator which way to act.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use vti_common::store::KeyspaceHandle;

use super::model::{RegistryRecord, RegistryStatus};
use super::storage::list_records;
use super::{RegistryError, TrustRegistryClient};

/// How the two views of one member's record disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum Disagreement {
    /// We published it; the registry does not have it. A lost write — the
    /// member is invisible to every other community.
    MissingAtRegistry,
    /// The registry has it; we have no record of publishing it.
    UnknownLocally,
    /// Both have it and disagree on whether the member is active.
    StatusMismatch,
}

impl Disagreement {
    /// Whether this disagreement means a member is *not* correctly published.
    ///
    /// `UnknownLocally` is excluded deliberately: an extra record at the
    /// registry does not make any member invisible, and treating it as a fault
    /// would make a benign leftover from an earlier deployment look like an
    /// outage.
    pub fn is_fault(self) -> bool {
        matches!(self, Self::MissingAtRegistry | Self::StatusMismatch)
    }
}

/// One member whose two views disagree.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DriftEntry {
    pub member_did: String,
    pub disagreement: Disagreement,
    /// Our view's status, when we hold a record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_status: Option<RegistryStatus>,
    /// The registry's view, when it holds a record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_status: Option<RegistryStatus>,
}

/// The result of one comparison.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DriftSnapshot {
    pub checked_at: DateTime<Utc>,
    /// Records in the local mirror.
    pub local_count: usize,
    /// Records the registry returned for this community's authority.
    pub registry_count: usize,
    /// Every disagreement, capped at [`MAX_REPORTED`].
    pub entries: Vec<DriftEntry>,
    /// Total disagreements found, which may exceed `entries.len()`.
    pub total: usize,
    /// Set when the comparison could not be made. The previous snapshot is
    /// retained rather than replaced, so a transient registry outage does not
    /// erase a real finding — but `checked_at` stops advancing, and this says
    /// why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DriftSnapshot {
    /// Disagreements that mean a member is not correctly published.
    pub fn fault_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.disagreement.is_fault())
            .count()
    }
}

/// How many disagreements a snapshot carries. A community whose registry
/// deployment was broken for a week can accumulate one per member; the count
/// stays exact while the list stays bounded.
pub const MAX_REPORTED: usize = 100;

/// Shared, cheap-to-clone handle to the latest comparison.
///
/// `None` until the first check completes — which is "not yet known", not
/// "no drift", and the diagnostics surface must not render the two alike.
#[derive(Debug, Clone, Default)]
pub struct DriftState {
    inner: Arc<RwLock<Option<DriftSnapshot>>>,
}

impl DriftState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> Option<DriftSnapshot> {
        self.inner.read().await.clone()
    }

    async fn publish(&self, snapshot: DriftSnapshot) {
        *self.inner.write().await = Some(snapshot);
    }

    /// Record that a check failed, keeping whatever was last known.
    ///
    /// A failed comparison is not evidence that drift has gone away. Replacing
    /// a real finding with an empty snapshot because the registry was briefly
    /// unreachable would clear an operator's alarm without fixing anything, so
    /// the entries stay and only `error` changes.
    async fn publish_error(&self, error: String) {
        let mut guard = self.inner.write().await;
        match guard.as_mut() {
            Some(existing) => existing.error = Some(error),
            None => {
                *guard = Some(DriftSnapshot {
                    checked_at: Utc::now(),
                    local_count: 0,
                    registry_count: 0,
                    entries: Vec::new(),
                    total: 0,
                    error: Some(error),
                })
            }
        }
    }
}

/// Compare the two views and publish the result.
///
/// Errors are recorded on the state rather than returned: the caller is a timer
/// with nowhere to report to, and a failed comparison is itself a thing the
/// diagnostics surface should say.
pub async fn check(
    client: &dyn TrustRegistryClient,
    registry_records_ks: &KeyspaceHandle,
    state: &DriftState,
) {
    let local = match list_records(registry_records_ks).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "drift check could not read the local registry mirror");
            state
                .publish_error(format!("local mirror unreadable: {e}"))
                .await;
            return;
        }
    };

    let remote = match client.list_records().await {
        Ok(rows) => rows,
        Err(e) => {
            debug!(error = %e, "drift check could not enumerate the trust registry");
            state
                .publish_error(format!("registry unreadable: {e}"))
                .await;
            return;
        }
    };

    state.publish(compare(&local, &remote)).await;
}

/// The comparison itself, pure so it can be tested without a registry.
pub fn compare(local: &[RegistryRecord], remote: &[RegistryRecord]) -> DriftSnapshot {
    use std::collections::BTreeMap;

    let local_by_did: BTreeMap<&str, &RegistryRecord> =
        local.iter().map(|r| (r.member_did.as_str(), r)).collect();
    let remote_by_did: BTreeMap<&str, &RegistryRecord> =
        remote.iter().map(|r| (r.member_did.as_str(), r)).collect();

    let mut entries = Vec::new();

    for (did, ours) in &local_by_did {
        match remote_by_did.get(did) {
            None => entries.push(DriftEntry {
                member_did: (*did).to_string(),
                disagreement: Disagreement::MissingAtRegistry,
                local_status: Some(ours.status),
                registry_status: None,
            }),
            Some(theirs) if theirs.status != ours.status => entries.push(DriftEntry {
                member_did: (*did).to_string(),
                disagreement: Disagreement::StatusMismatch,
                local_status: Some(ours.status),
                registry_status: Some(theirs.status),
            }),
            Some(_) => {}
        }
    }

    for (did, theirs) in &remote_by_did {
        if !local_by_did.contains_key(did) {
            entries.push(DriftEntry {
                member_did: (*did).to_string(),
                disagreement: Disagreement::UnknownLocally,
                local_status: None,
                registry_status: Some(theirs.status),
            });
        }
    }

    // Faults first: a truncated list must carry the entries an operator has to
    // act on, not whichever DIDs happened to sort lowest.
    entries.sort_by_key(|e| (!e.disagreement.is_fault(), e.member_did.clone()));
    let total = entries.len();
    entries.truncate(MAX_REPORTED);

    DriftSnapshot {
        checked_at: Utc::now(),
        local_count: local.len(),
        registry_count: remote.len(),
        entries,
        total,
        error: None,
    }
}

/// A registry client that cannot enumerate returns this, so the drift check
/// reports "not supported here" rather than looking like an outage.
pub fn unsupported() -> RegistryError {
    RegistryError::Permanent(
        "this trust-registry transport cannot enumerate records, so drift cannot be checked".into(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn active(did: &str) -> RegistryRecord {
        RegistryRecord::fresh_active(did)
    }

    fn departed(did: &str) -> RegistryRecord {
        RegistryRecord::departed(did, Utc::now(), None)
    }

    /// The case the whole module exists for: we published a member, the write
    /// was lost, and nothing else in the service would ever say so.
    #[test]
    fn a_member_we_published_and_the_registry_lacks_is_a_fault() {
        let snap = compare(&[active("did:key:zGone")], &[]);
        assert_eq!(snap.total, 1);
        assert_eq!(
            snap.entries[0].disagreement,
            Disagreement::MissingAtRegistry
        );
        assert_eq!(snap.fault_count(), 1);
    }

    /// An extra record at the registry makes no member invisible, so it is
    /// reported without being counted as a fault.
    #[test]
    fn a_record_only_the_registry_has_is_reported_but_not_a_fault() {
        let snap = compare(&[], &[active("did:key:zExtra")]);
        assert_eq!(snap.total, 1);
        assert_eq!(snap.entries[0].disagreement, Disagreement::UnknownLocally);
        assert_eq!(snap.fault_count(), 0);
    }

    /// A removal that half-landed: both sides hold the record and disagree on
    /// whether the member is still active.
    #[test]
    fn a_status_disagreement_is_a_fault() {
        let snap = compare(&[departed("did:key:zLeft")], &[active("did:key:zLeft")]);
        assert_eq!(snap.entries[0].disagreement, Disagreement::StatusMismatch);
        assert_eq!(snap.entries[0].local_status, Some(RegistryStatus::Departed));
        assert_eq!(
            snap.entries[0].registry_status,
            Some(RegistryStatus::Active)
        );
        assert_eq!(snap.fault_count(), 1);
    }

    /// Agreement is silence. Counts still report, so an operator can tell
    /// "checked and matched" from "never checked".
    #[test]
    fn agreement_produces_no_entries_but_still_reports_counts() {
        let snap = compare(&[active("did:key:zA")], &[active("did:key:zA")]);
        assert!(snap.entries.is_empty());
        assert_eq!(snap.local_count, 1);
        assert_eq!(snap.registry_count, 1);
        assert_eq!(snap.total, 0);
    }

    /// Truncation keeps the actionable half. A community with more benign
    /// extras than lost writes must not have the lost writes pushed off the end.
    #[test]
    fn truncation_keeps_faults_ahead_of_benign_entries() {
        let local: Vec<_> = (0..5)
            .map(|i| active(&format!("did:key:zLost{i}")))
            .collect();
        let remote: Vec<_> = (0..MAX_REPORTED + 50)
            .map(|i| active(&format!("did:key:zExtra{i:04}")))
            .collect();

        let snap = compare(&local, &remote);
        assert_eq!(snap.total, 5 + MAX_REPORTED + 50);
        assert_eq!(snap.entries.len(), MAX_REPORTED);
        assert_eq!(
            snap.fault_count(),
            5,
            "every lost write survives truncation: {:?}",
            snap.entries.iter().take(8).collect::<Vec<_>>()
        );
    }

    /// A failed check keeps the last real finding. Replacing it with an empty
    /// snapshot would clear an operator's alarm because the registry blipped.
    #[tokio::test]
    async fn a_failed_check_annotates_rather_than_erases() {
        let state = DriftState::new();
        state
            .publish(compare(&[active("did:key:zGone")], &[]))
            .await;

        state
            .publish_error("registry unreadable: timeout".into())
            .await;

        let snap = state.snapshot().await.unwrap();
        assert_eq!(snap.total, 1, "the finding survives");
        assert!(snap.error.as_deref().unwrap().contains("timeout"));
    }

    /// Before the first check there is no snapshot at all — "not yet known",
    /// which a consumer must not render as "no drift".
    #[tokio::test]
    async fn state_is_empty_until_the_first_check() {
        assert!(DriftState::new().snapshot().await.is_none());
    }
}
