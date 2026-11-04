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
//! - **Member-party notifications** (VTI-NTF-061): `crate::notifications::election`, whose
//!   one sender this pass is.
//! - **Accepted presentations** (show/0.6 item 8.6): the `id` of a read whose presentation was
//!   accepted is forgotten once its acceptance window has passed.

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

/// How often, at most, a head is kept for a board's election while voting is open: a board
/// shows the ballot count of the latest kept head (VTI-BRD-033), so it is read more often.
pub const BOARD_CHECKPOINT_EVERY: chrono::Duration = chrono::Duration::minutes(30);

/// The checkpoints a board's election spreads over its voting period, leaving room under the
/// 256 an election keeps for the first head and the final one. Past 256 none is kept but the
/// final, so a fixed 30-minute pace would freeze a board's ballot count after about five days.
const BOARD_CHECKPOINTS_PER_PERIOD: i32 = 240;

/// The pace of a board election's checkpoints: every 30 minutes, or slower where its voting
/// period would otherwise outrun the checkpoints it may keep.
fn board_checkpoint_every(rec: &store::ElectionRecord) -> chrono::Duration {
    let spread = (rec.voting_closes - rec.voting_opens) / BOARD_CHECKPOINTS_PER_PERIOD;
    spread.max(BOARD_CHECKPOINT_EVERY)
}

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
    if let Err(e) = store::prune_presentations(state.elections.ks(), now).await {
        warn!(error = %e, "could not forget expired presentation acceptances this pass");
    }
    for rec in store::all(state.elections.ks()).await? {
        let id = rec.election_id.clone();
        // The member party a credential roll names is told once the election is
        // registered, and told again if it is withdrawn (VTI-NTF-061). Before `settle`,
        // which may move the record on: the notice reads the standing it was given.
        if let Err(e) = crate::notifications::election::settle(state, &rec, now).await {
            warn!(election = %id, error = %e, "could not settle a member-party notification this pass");
        }
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
            // Once voting has closed, the community authorizes exactly the decryption the board
            // calls for (CONVENTIONS §9.7).
            if closed && !rec.decryption_authorized && rec.manifest.get("trustees").is_some() {
                ops::authorize_decryption(state, &rec.election_id).await;
            }
            if now >= rec.voting_closes {
                discard_pre_credentials(state, &rec.election_id).await?;
            }
            // A board's facilitators select with the result in view (VTI-BRD-040): once voting
            // has closed and the final head is kept, verify the published result and keep it,
            // uncertified. Best effort: a result not published yet is tried on the next pass.
            if closed
                && rec.final_checkpoint
                && rec.certified.is_none()
                && rec.verified.is_none()
                && crate::boards::is_board_election(&rec.election_id)
                && let Err(e) = ops::verify_and_keep(state, &rec.election_id, now).await
            {
                tracing::debug!(election = %rec.election_id, error = ?e, "a board election's result is not verified yet");
            }
        }
        // A pre-credential is discarded once voting is over, however it ended (tickets/issue
        // item 10).
        Standing::Tallied | Standing::Cancelled => {
            discard_pre_credentials(state, &rec.election_id).await?;
        }
        _ => {}
    }
    Ok(())
}

/// Whether the community last had a head answered [`CHECKPOINT_EVERY`] ago or more (or never),
/// by its own clock. Never by a head's `issuedAt`: that is the ballot box's clock, and a box
/// that dated its heads ahead would put every later checkpoint off, leaving it free to show
/// different boards in between.
fn checkpoint_due(rec: &store::ElectionRecord, now: DateTime<Utc>) -> bool {
    let every = if crate::boards::is_board_election(&rec.election_id) {
        board_checkpoint_every(rec)
    } else {
        CHECKPOINT_EVERY
    };
    rec.checkpoint_asked_at
        .is_none_or(|at| now - at >= every || now < at)
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
        roll_member_of: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checkpoint_is_paced_by_the_communitys_clock_not_the_boxs() {
        let now = Utc::now();
        let mut rec = store::test_record(now);
        // A head the box dated a year ahead puts nothing off.
        rec.checkpoints.push(serde_json::json!({
            "head": { "issuedAt": (now + chrono::Duration::days(365)).to_rfc3339() }
        }));
        assert!(checkpoint_due(&rec, now));
        rec.checkpoint_asked_at = Some(now);
        assert!(!checkpoint_due(&rec, now + chrono::Duration::hours(1)));
        assert!(checkpoint_due(&rec, now + CHECKPOINT_EVERY));
        // Its own clock set back: due again, rather than never.
        assert!(checkpoint_due(&rec, now - chrono::Duration::hours(1)));
    }

    #[test]
    fn vti_brd_033_a_long_boards_ballot_count_keeps_moving_to_the_end() {
        let now = Utc::now();
        let mut rec = store::test_record(now);
        rec.election_id = "board.brd_Uc7N2qLm4Rt8Vx1Z00.ida_Pk3Wq9Ls2Dn6Hy4B00".into();
        // A short period is read every 30 minutes.
        rec.voting_opens = now;
        rec.voting_closes = now + chrono::Duration::days(2);
        assert_eq!(board_checkpoint_every(&rec), BOARD_CHECKPOINT_EVERY);
        // A long one is spread so its checkpoints never run out before it closes.
        rec.voting_closes = now + chrono::Duration::days(30);
        let every = board_checkpoint_every(&rec);
        assert!(every > BOARD_CHECKPOINT_EVERY);
        assert!((rec.voting_closes - rec.voting_opens).num_seconds() / every.num_seconds() <= 240);
        rec.checkpoint_asked_at = Some(now);
        assert!(!checkpoint_due(&rec, now + BOARD_CHECKPOINT_EVERY));
        assert!(checkpoint_due(&rec, now + every));
    }
}
