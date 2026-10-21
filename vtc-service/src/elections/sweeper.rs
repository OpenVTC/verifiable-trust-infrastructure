//! The registrar's background pass, once a minute:
//!
//! - **Registration delivery** (create item 8). The one retry owner for a registration the
//!   ballot box has not answered: each pending election is delivered again when its backoff
//!   allows. A refusal on a later delivery leaves the election `registrationRefused`, which only
//!   a cancellation clears.
//! - **Checkpoints** (show item 5): a board head kept when voting opens, every
//!   [`CHECKPOINT_EVERY`] while it is open, and once it has closed, so certification can hold the
//!   final board to each.
//! - **Pre-credentials** (tickets/issue item 10): discarded once voting has closed, when no
//!   resend can be useful.

use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::{info, warn};
use vti_common::audit::{AuditEvent, ElectionChangedData};

use super::ops::{self, Delivered};
use super::store::{self, Standing};
use crate::error::AppError;
use crate::server::AppState;

const PASS_INTERVAL: Duration = Duration::from_secs(60);

/// How often a head is kept while voting is open.
pub const CHECKPOINT_EVERY: chrono::Duration = chrono::Duration::hours(6);

/// Run [`pass`] every minute until shutdown.
pub fn spawn(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = pass(&state, Utc::now()).await {
                warn!(error = %e, "election pass failed; it runs again within the minute");
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(PASS_INTERVAL) => {}
            }
        }
    })
}

/// One pass over every election.
///
/// # Errors
/// A store failure reading the elections; a failure on one election is logged and the pass
/// goes on.
pub async fn pass(state: &AppState, now: DateTime<Utc>) -> Result<(), AppError> {
    for rec in store::all(state.elections.ks()).await? {
        let id = rec.election_id.clone();
        if let Err(e) = settle(state, rec, now).await {
            warn!(election = %id, error = %e, "could not settle an election this pass");
        }
    }
    Ok(())
}

async fn settle(
    state: &AppState,
    rec: store::ElectionRecord,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let ks = state.elections.ks();
    match rec.standing {
        Standing::PendingRegistration
            if !rec.issuance_stopped && rec.delivery.as_ref().is_some_and(|d| d.next_at <= now) =>
        {
            let id = rec.election_id.clone();
            let (answer, refused) = match ops::deliver_registration(state, rec, now).await? {
                Delivered::Registered(_) => ("success".to_string(), false),
                Delivered::Pending(_) => return Ok(()),
                Delivered::Refused {
                    mut rec,
                    code,
                    message,
                } => {
                    rec.standing = Standing::RegistrationRefused;
                    rec.refusal = Some(store::BoxRefusal {
                        code: code.clone(),
                        message,
                    });
                    store::put(ks, &rec).await?;
                    (code, true)
                }
            };
            info!(election = %id, refused, "a pending registration was answered");
            audit(
                state,
                &id,
                if refused {
                    "registrationRefused"
                } else {
                    "registered"
                },
                answer,
            )
            .await;
        }
        Standing::Registered | Standing::Closed => {
            let closed = now >= rec.voting_closes || rec.standing == Standing::Closed;
            if closed {
                if !rec.final_checkpoint {
                    ops::checkpoint(state, &rec.election_id, true).await;
                }
            } else if now >= rec.voting_opens && checkpoint_due(&rec, now) {
                ops::checkpoint(state, &rec.election_id, false).await;
            }
            // The trustees form the key before voting opens, at the latest; keep reading until
            // it is held.
            if !closed && rec.election_key.is_none() && rec.manifest.get("trustees").is_some() {
                ops::read_election_key(state, &rec.election_id).await;
            }
            if now >= rec.voting_closes {
                discard_pre_credentials(state, &rec.election_id).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether the last head kept is older than [`CHECKPOINT_EVERY`] (or there is none).
fn checkpoint_due(rec: &store::ElectionRecord, now: DateTime<Utc>) -> bool {
    rec.checkpoints
        .last()
        .and_then(|c| c["head"]["issuedAt"].as_str())
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .is_none_or(|at| now - at.with_timezone(&Utc) >= CHECKPOINT_EVERY)
}

async fn discard_pre_credentials(state: &AppState, election_id: &str) -> Result<(), AppError> {
    let ks = state.elections.ks();
    for mut t in store::tickets(ks, election_id).await? {
        if t.pre_credential.take().is_some() {
            store::replace_ticket(ks, &t).await?;
        }
    }
    Ok(())
}

async fn audit(state: &AppState, election_id: &str, change: &str, answer: String) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let community = ops::community_did(state).await;
    let event = AuditEvent::ElectionChanged(ElectionChangedData {
        election_id: election_id.to_string(),
        change: change.to_string(),
        manifest_digest: None,
        binding: None,
        action_id: None,
        ballot_box_answer: Some(answer),
        reason: None,
        head_tree_size: None,
        head_root_hash: None,
        result_digest: None,
        attestation_issuers: Vec::new(),
    });
    if let Err(e) = writer.write(&community, None, event).await {
        warn!(election = election_id, error = %e, "could not audit a registration's answer");
    }
}
