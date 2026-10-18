//! Erasing a retired field's values once its retention period has passed
//! (`vtc/directory/fields/retire/0.1` item 4, VTI-DIR-015).
//!
//! The one owner of the purge. A retired field is hidden from every read the
//! moment it is retired; this erases what it held, an hour or so after the
//! field's `purgeAfter`, and records that it did. A field once purged is
//! marked, so a pass reads every card only for a field that is due.

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

pub fn spawn(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = purge_due(&state).await {
                warn!(error = %e, "directory retention pass failed; it runs again within the hour");
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(PASS_INTERVAL) => {}
            }
        }
    })
}
