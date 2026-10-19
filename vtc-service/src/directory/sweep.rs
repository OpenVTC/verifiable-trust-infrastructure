//! The directory's hourly pass:
//!
//! - erasing a retired field's values once its retention period has passed
//!   (`vtc/directory/fields/retire/0.1` item 4, VTI-DIR-015) — the one owner
//!   of the purge. A retired field is hidden from every read the moment it is
//!   retired; this erases what it held, an hour or so after the field's
//!   `purgeAfter`, and records that it did. A field once purged is marked, so
//!   a pass reads every card only for a field that is due;
//! - erasing pictures no card and no live upload holds (`images/upload`
//!   item 6);
//! - withdrawing external cards whose public values moved on in a way no
//!   write path saw — a `directory` policy change, a suspension — and
//!   repairing any recognition record whose card pointer is not the card now
//!   published (`card/publish` items 7 and 8).

use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};
use vti_common::audit::{AuditEvent, DirectoryFieldChangedData};
use vti_common::error::AppError;

use super::{cards, fields};
use crate::server::AppState;

/// The audit actor of a purge: the community itself, not an administrator.
pub const ACTOR: &str = "vtc:directory-retention";

const PASS_INTERVAL: Duration = Duration::from_secs(3600);

fn purged_key(field: &str) -> Vec<u8> {
    format!("purged:{field}").into_bytes()
}

/// One pass: every retired field whose purge is due and not yet done.
/// Returns the fields purged.
pub async fn purge_due(state: &AppState) -> Result<Vec<String>, AppError> {
    let ks = state.directory.ks();
    let mut done = Vec::new();
    for key in fields::due_for_purge(ks, Utc::now()).await? {
        if ks.get_raw(purged_key(&key)).await?.is_some() {
            continue;
        }
        // Recorded first: an erasure without its record is the one outcome
        // worse than an erasure retried.
        if let Some(w) = state.audit_writer.as_ref() {
            w.write(
                ACTOR,
                None,
                AuditEvent::DirectoryFieldChanged(DirectoryFieldChangedData {
                    key: key.clone(),
                    change: "purge".into(),
                    widens: false,
                    reason: None,
                }),
            )
            .await?;
        }
        let cards_held = cards::purge_field(ks, &key).await?;
        ks.insert_raw(purged_key(&key), Utc::now().to_rfc3339().into_bytes())
            .await?;
        info!(field = %key, cards_held, "erased a retired directory field's values");
        done.push(key);
    }
    Ok(done)
}

/// One pass over pictures and external cards. Returns the pictures erased,
/// the cards withdrawn and the registry records queued for repair.
pub async fn settle(state: &AppState) -> Result<(usize, usize, usize), AppError> {
    let erased = super::images::collect(state.directory.ks(), Utc::now()).await?;
    let withdrawn = super::external::reconcile_all(state).await?;
    let repaired = repair_pointers(state).await?;
    Ok((erased, withdrawn, repaired))
}

/// Queue a re-publication of every recognition record whose card pointer
/// differs from the card now published, unless one is already queued. The
/// audit tail queues one at every publication and withdrawal; this is the
/// retry for one that never got there.
async fn repair_pointers(state: &AppState) -> Result<usize, AppError> {
    use crate::registry::model::{SyncJob, SyncJobKind};
    if state.registry_client.is_none() {
        return Ok(0);
    }
    let queued: std::collections::BTreeSet<String> =
        crate::registry::storage::list_sync_jobs(&state.sync_queue_ks)
            .await?
            .into_iter()
            .filter(|j| j.state != crate::registry::model::SyncJobState::Failed)
            .map(|j| j.member_did)
            .collect();
    let mut repaired = 0;
    for card in cards::all(state.directory.ks()).await? {
        let Some(record) =
            crate::registry::storage::get_record(&state.registry_records_ks, &card.did).await?
        else {
            continue;
        };
        let pointed = record
            .directory_card
            .as_ref()
            .map(|p| p.card_digest.as_str());
        if pointed == card.published_digest() || queued.contains(&card.did) {
            continue;
        }
        crate::registry::storage::store_sync_job(
            &state.sync_queue_ks,
            &SyncJob::fresh(SyncJobKind::UpdateMember, &card.did),
        )
        .await?;
        repaired += 1;
    }
    Ok(repaired)
}

pub fn spawn(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = purge_due(&state).await {
                warn!(error = %e, "directory retention pass failed; it runs again within the hour");
            }
            match settle(&state).await {
                Ok((0, 0, 0)) => {}
                Ok((erased, withdrawn, repaired)) => info!(
                    erased,
                    withdrawn, repaired, "directory pass: pictures erased, external cards settled"
                ),
                Err(e) => {
                    warn!(error = %e, "directory picture and external-card pass failed; it runs again within the hour")
                }
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(PASS_INTERVAL) => {}
            }
        }
    })
}
