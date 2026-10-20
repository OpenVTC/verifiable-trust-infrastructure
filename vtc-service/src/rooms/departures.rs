//! A member who leaves the community leaves the rooms it owns
//! (`vtc/rooms/community/members/add` item 6: the community **SHOULD** remove the member from
//! every room it owns when they leave the community).
//!
//! # Recorded at the departure, driven by one owner
//!
//! A departure never waits on the community's VTA. Where it happens it records a
//! [`PendingRemoval`](super::community::PendingRemoval) per room the member holds an admission or an open offer in
//! ([`CommunityRooms::record_departure`]), in the `community_rooms` keyspace — durable and
//! backed up — and this module's worker is the **one retry owner** that drives each to
//! completion, exactly as an administrator's `members/remove/0.2` does ([`remove_member`],
//! trust-tasks-tf #804): on `open` and `attributed` rooms the member's credentials — an open
//! offer's too — are withdrawn at the host (`rooms/owner/revoke`, or
//! `rooms/owner/group/remove/0.3` — 0.2 on an older VTA — which also advances an `attributed`
//! room past them); on a
//! `private` room they leave the group (`group/remove/0.1`) and an open offer is withdrawn
//! here. All of it **before** the removal is recorded (R2.1). The removal and the dropping of the owed row are one batch.
//!
//! A VTA that does not answer, or refuses, is tried again with capped exponential backoff,
//! and the row says so (`attempts`, `lastError`) where administrators read the room
//! (`ext["org.openvtc"].departureRemovals`). An attempt whose answer was lost is settled by
//! the next, which the VTA answers `notMember` — a removal of someone already removed is
//! success. An administrator removing the member by hand settles the row too.
//!
//! # Where departures come from
//!
//! Recorded explicitly where they happen — the leave and admin-remove ceremony
//! (`ceremony::execute::depart`), an ACL revocation (`routes::acl::remove_entry`), a
//! suspension (`admin_actions::save`), and `vtc acl remove` offline — and found by
//! [`reconcile`] on every sweep for what has no event: an ACL entry that **expired**, and any
//! of the above whose recording a crash cut off. The reconciler reads only durable state, so a
//! restart loses nothing; it waits [`GRACE`] before acting on what it sees, so a write in
//! flight (a key rotation moves the entry, then the member row) is never read as a departure.
//!
//! # Not undone by rejoining
//!
//! A removal owed is completed even if the person has since rejoined: they left, and a
//! returning member is admitted to a room again only by an administrator. Nothing here ever
//! re-adds anyone.

use std::collections::HashSet;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::rooms::owner::group::remove::v0_1 as owner_remove;
use trust_tasks_rs::specs::rooms::owner::group::remove::v0_2 as owner_remove_v0_2;
use trust_tasks_rs::specs::rooms::owner::group::remove::v0_3 as owner_remove_v0_3;
use trust_tasks_rs::specs::rooms::owner::revoke::v0_1 as owner_revoke;
use vti_common::audit::{AuditEvent, CommunityRoomChangedData};
use vti_common::error::AppError;

use super::community::{
    ADVANCE_TIMEOUT, CommunityRooms, DepartureCause, HolderError, KeyHolder, MemberRecord,
    OwnedRoom,
};
use crate::server::AppState;

/// The audit actor of a removal made because the member left: the community itself, not an
/// administrator.
pub const ACTOR: &str = "vtc:member-departure";

/// How long the reconciler sees a member no longer active before it records the departure.
pub const GRACE: chrono::Duration = chrono::Duration::seconds(60);

/// How often the worker runs when nothing wakes it.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// The first retry's delay; each further one doubles, up to [`BACKOFF_CAP_SECS`].
const BACKOFF_BASE_SECS: i64 = 30;
const BACKOFF_CAP_SECS: i64 = 60 * 60;

/// What removal does not do — said in the audit row of every removal, and in the answer's
/// `ext` of an administrator's as a courtesy. `vtc/rooms/community/members/remove` item 4
/// (clarified in place, trust-tasks-tf #796) requires only that neither represent a removal as
/// recalling what was read, re-sealing what was written or revoking the authority credential.
pub const REMOVAL_NOTICE: &str = "Removal ends access to what is written from now on. It recalls \
     nothing the member already read, and their authority credential is not revoked: a host \
     honours it until it expires, though on a sealed room it opens nothing written after this.";

const OWNER_GROUP_REMOVE: &str = <owner_remove::Payload as Payload>::TYPE_URI;
const OWNER_GROUP_REMOVE_V0_2: &str = <owner_remove_v0_2::Payload as Payload>::TYPE_URI;
const OWNER_GROUP_REMOVE_V0_3: &str = <owner_remove_v0_3::Payload as Payload>::TYPE_URI;
const OWNER_REVOKE: &str = <owner_revoke::Payload as Payload>::TYPE_URI;

/// What a removal at `vtc/rooms/community/members/remove/0.2` does not do, per tier — the
/// audit row's note and, for an administrator's, a courtesy in the answer's `ext` beside
/// the structured members a caller reads instead (item 4).
pub fn removal_notice(withdrawn_at_host: bool) -> &'static str {
    if withdrawn_at_host {
        "Removal ends the member's access at once: the room's host refuses every credential \
         the room issued them, and anything they delegated, from `revokedAt`. It recalls \
         nothing they already read or saved, and re-seals nothing written before."
    } else {
        "On a private room a member cannot be withdrawn one at a time: they leave the room's \
         group, so nothing written from the new epoch on opens for them, but the host honours \
         their credentials until `validUntil`. It recalls nothing they already read."
    }
}

/// What a removal did at the community's VTA.
#[derive(Debug, Default)]
pub struct Removed {
    /// The first epoch sealed without the member, on a sealed tier.
    pub epoch: Option<u64>,
    /// The room's revocation list head the host accepted, and the withdrawal's
    /// `revokedAt` — on `open` and `attributed` rooms.
    pub revocation: Option<(Value, String)>,
}

fn request<P: serde::de::DeserializeOwned + serde::Serialize>(
    payload: Value,
) -> Result<Value, HolderError> {
    let p: P = serde_json::from_value(payload)
        .map_err(|e| HolderError::Unavailable(format!("a request to the community's VTA: {e}")))?;
    serde_json::to_value(p)
        .map_err(|e| HolderError::Unavailable(format!("a request to the community's VTA: {e}")))
}

fn shape<R: serde::de::DeserializeOwned>(task: &str, answer: &Value) -> Result<R, HolderError> {
    serde_json::from_value(answer.clone()).map_err(|e| {
        HolderError::Unavailable(format!(
            "the community's VTA answered {task} in a shape its specification does not define: {e}"
        ))
    })
}

/// Remove `member` from `room` as `vtc/rooms/community/members/remove/0.2` item 2 does —
/// the one removal an administrator's request and a departure both make
/// (trust-tasks-tf #804):
///
/// - `open`, or an open offer on `attributed`: the VTA **withdraws** them —
///   `rooms/owner/revoke`, one `subject` withdrawal, delivered to `host` (this community,
///   the room's host) — and the removal holds only once the host accepted it;
/// - `attributed`, admitted: `rooms/owner/group/remove` at 0.3 (0.2 on a VTA that does not
///   serve it) — withdrawn first, then the room advances; a member with no leaf is withdrawn
///   alone. An earlier removal the VTA was still settling and had to give up is refused
///   `earlierRemovalRefused`, with nothing of this one done: a refusal like any other here,
///   and the next attempt proceeds;
/// - `private`, admitted: `rooms/owner/group/remove` at 0.1 — the group alone, since a
///   private room's host cannot be told whom to refuse. (A private room's open offer asks
///   the VTA nothing; the caller does not call this for one.)
///
/// A host that did not accept the withdrawal is a refusal or an unknown outcome — never a
/// removal.
pub async fn remove_member(
    holder: &KeyHolder,
    room: &OwnedRoom,
    host: &str,
    member: &str,
    offered: bool,
    reason: &str,
) -> Result<Removed, HolderError> {
    let room_id = room.room_id.as_str();
    if room.visibility == "private" {
        return remove_from_group(holder, room_id, host, member, reason)
            .await
            .map(|epoch| Removed {
                epoch,
                revocation: None,
            });
    }
    if room.visibility != "open" && !offered {
        // 0.3, so an earlier removal the VTA was still settling is never discarded inside
        // this one (item 8); 0.2 on a VTA that does not serve 0.3, whose request and
        // response are the same. Every code 0.2 declares, 0.3 declares under the same string.
        let req = request::<owner_remove_v0_3::Payload>(json!({
            "roomId": room_id,
            "host": host,
            "member": member,
            "signingKeyId": room.signing_key_id,
            "reason": reason,
        }))?;
        let mut asked = holder
            .ask(OWNER_GROUP_REMOVE_V0_3, req.clone(), ADVANCE_TIMEOUT)
            .await;
        if matches!(&asked, Err(HolderError::Refused { code, .. })
            if code == "unsupportedType" || code == "unsupportedVersion")
        {
            asked = holder
                .ask(OWNER_GROUP_REMOVE_V0_2, req, ADVANCE_TIMEOUT)
                .await;
        }
        match asked {
            Ok(answer) => {
                let r: owner_remove_v0_3::Response = shape("rooms/owner/group/remove", &answer)?;
                return Ok(Removed {
                    epoch: u64::try_from(r.epoch).ok(),
                    revocation: Some((
                        answer["revocation"].clone(),
                        answer["revokedAt"].as_str().unwrap_or_default().to_string(),
                    )),
                });
            }
            // No leaf — admitted here, never joined at the VTA: withdrawn alone, below.
            Err(HolderError::Refused { code, .. })
                if code == owner_remove_v0_3::error_codes::NOT_MEMBER.code => {}
            Err(HolderError::Refused { code, message })
                if code == owner_remove_v0_3::error_codes::HOST_UNREACHABLE.code =>
            {
                return Err(HolderError::Unavailable(message));
            }
            Err(e) => return Err(e),
        }
    }

    let req = request::<owner_revoke::Payload>(json!({
        "roomId": room_id,
        "signingKeyId": room.signing_key_id,
        "hosts": [host],
        "withdraw": [{ "kind": "subject", "subject": member }],
        "reason": reason,
    }))?;
    let answer = holder.ask(OWNER_REVOKE, req, ADVANCE_TIMEOUT).await?;
    shape::<owner_revoke::Response>("rooms/owner/revoke", &answer)?;
    // Only a host that answered with the list's head enforces it (`rooms/owner/revoke`
    // item 5).
    let delivery = answer["deliveries"]
        .as_array()
        .and_then(|d| d.first())
        .cloned()
        .unwrap_or(Value::Null);
    match delivery["outcome"].as_str() {
        Some("accepted") => {}
        Some("refused") => {
            return Err(HolderError::Refused {
                code: delivery["code"].as_str().unwrap_or_default().to_string(),
                message: "this community, the room's host, refused the room's revocation list"
                    .into(),
            });
        }
        _ => {
            return Err(HolderError::Unavailable(
                "the room's revocation list was signed, but this community did not confirm it \
                 as the room's host; it is delivered again on the next attempt"
                    .into(),
            ));
        }
    }
    // The withdrawal's time: the latest entry naming the member.
    let revoked_at = answer["list"]["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["kind"] == "subject" && e["subject"] == member)
        .filter_map(|e| e["revokedAt"].as_str())
        .max()
        .unwrap_or_default()
        .to_string();
    Ok(Removed {
        epoch: None,
        revocation: Some((answer["head"].clone(), revoked_at)),
    })
}

/// The delay before the next attempt, after `attempts` have failed.
pub fn backoff(attempts: u32) -> chrono::Duration {
    let shift = attempts.saturating_sub(1).min(16);
    chrono::Duration::seconds((BACKOFF_BASE_SECS << shift).min(BACKOFF_CAP_SECS))
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Have the community's VTA remove `member` from `room_id`'s group, advancing the room past
/// them. `Ok(epoch)`: removed, with the first epoch sealed without them when the VTA said;
/// `Ok(None)` too when they hold no leaf — nothing to advance past, and removed is what is
/// true. A host that did not answer the VTA, or an answer that cannot be read, is
/// [`HolderError::Unavailable`]: the outcome is unknown and the VTA settles its own pending
/// advance on the next request.
pub async fn remove_from_group(
    holder: &KeyHolder,
    room_id: &str,
    host: &str,
    member: &str,
    reason: &str,
) -> Result<Option<u64>, HolderError> {
    let request: owner_remove::Payload = serde_json::from_value(json!({
        "roomId": room_id,
        "host": host,
        "member": member,
        "reason": reason,
    }))
    .map_err(|e| HolderError::Unavailable(format!("a request to the community's VTA: {e}")))?;
    let request = serde_json::to_value(request)
        .map_err(|e| HolderError::Unavailable(format!("a request to the community's VTA: {e}")))?;
    match holder
        .ask(OWNER_GROUP_REMOVE, request, ADVANCE_TIMEOUT)
        .await
    {
        Ok(answer) => serde_json::from_value::<owner_remove::Response>(answer)
            .map(|r| u64::try_from(r.epoch).ok())
            .map_err(|e| {
                HolderError::Unavailable(format!(
                    "the community's VTA answered rooms/owner/group/remove in a shape its \
                     specification does not define: {e}"
                ))
            }),
        Err(HolderError::Refused { code, .. })
            if code == owner_remove::error_codes::NOT_MEMBER.code =>
        {
            Ok(None)
        }
        Err(HolderError::Refused { code, message })
            if code == owner_remove::error_codes::HOST_UNREACHABLE.code =>
        {
            Err(HolderError::Unavailable(message))
        }
        Err(e) => Err(e),
    }
}

/// Record `member`'s departure from the community where it happens: every removal it owes,
/// durably, before the worker is woken. Never asks the VTA.
pub async fn on_departure(
    state: &AppState,
    member: &str,
    cause: DepartureCause,
) -> Result<(), AppError> {
    state
        .community_rooms
        .record_departure(member, cause, Utc::now())
        .await
        .map(|_| ())
}

/// Why `did` is no longer an active member, read from durable state, or `None` while they
/// still are one (or the state says nothing either way).
async fn departure_of(
    state: &AppState,
    did: &str,
    now: DateTime<Utc>,
) -> Result<Option<DepartureCause>, AppError> {
    let entry = crate::acl::get_acl_entry(&state.acl_ks, did).await?;
    let member = crate::members::storage::get_member(&state.members_ks, did).await?;
    if member.as_ref().is_some_and(|m| m.is_removed()) {
        return Ok(Some(DepartureCause::Removed));
    }
    Ok(match entry {
        Some(e) if e.is_expired(now.timestamp().max(0) as u64) => Some(DepartureCause::Expired),
        Some(e) if e.is_suspended() => Some(DepartureCause::Suspended),
        Some(_) => None,
        // No entry, member row still in place: the entry was revoked. No entry and no member
        // row is a purge — recorded where it happened — or a key rotation, which is not a
        // departure (the entry and the row moved to the successor).
        None if member.is_some() => Some(DepartureCause::AclRemoved),
        None => None,
    })
}

/// Find departures nothing recorded — an ACL entry that expired, or a recording a crash cut
/// off — among the members holding an admission or an open offer, and record each once it
/// has been seen for [`GRACE`]. Answers how many removals were recorded.
pub async fn reconcile(state: &AppState, now: DateTime<Utc>) -> Result<usize, AppError> {
    let cr = &state.community_rooms;
    let mut holding = HashSet::new();
    for room in cr.rooms().await? {
        for m in cr.members(&room.room_id).await? {
            if m.state != MemberRecord::REMOVED {
                holding.insert(m.member);
            }
        }
    }
    let mut due = Vec::new();
    {
        let mut departed = Vec::new();
        for did in &holding {
            if let Some(cause) = departure_of(state, did, now).await? {
                departed.push((did.clone(), cause));
            }
        }
        let mut seen = cr.seen_inactive.lock().expect("seen lock");
        seen.retain(|did, _| departed.iter().any(|(d, _)| d == did));
        for (did, cause) in departed {
            let first = *seen.entry(did.clone()).or_insert(now);
            if now - first >= GRACE {
                seen.remove(&did);
                due.push((did, cause));
            }
        }
    }
    let mut recorded = 0;
    for (did, cause) in due {
        recorded += cr.record_departure(&did, cause, now).await?;
    }
    Ok(recorded)
}

/// What one pass of the worker did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DriveReport {
    /// Removals completed: recorded here, after the VTA where the room is sealed.
    pub removed: usize,
    /// Owed removals found already settled (removed by hand, or gone with their room).
    pub settled: usize,
    /// Attempts that did not complete and are scheduled again.
    pub retrying: usize,
}

/// Drive every owed removal whose time has come.
pub async fn drive(state: &AppState, now: DateTime<Utc>) -> Result<DriveReport, AppError> {
    let mut report = DriveReport::default();
    // Once the VTA has not answered in a pass, the pass stops asking it: each ask waits out
    // its timeout, and the rows wait for the next pass without spending an attempt.
    let mut vta_down = false;
    for p in state.community_rooms.pending_removals().await? {
        let due = DateTime::parse_from_rfc3339(&p.next_attempt_at)
            .map(|t| t.with_timezone(&Utc) <= now)
            .unwrap_or(true);
        if due {
            drive_one(
                state,
                &p.room_id,
                &p.member,
                now,
                &mut vta_down,
                &mut report,
            )
            .await?;
        }
    }
    Ok(report)
}

async fn drive_one(
    state: &AppState,
    room_id: &str,
    member: &str,
    now: DateTime<Utc>,
    vta_down: &mut bool,
    report: &mut DriveReport,
) -> Result<(), AppError> {
    let cr: &CommunityRooms = &state.community_rooms;
    let guard = cr.lock().await;
    // Re-read under the lock: an administrator's removal may have settled it meanwhile.
    let Some(pending) = cr.pending_removal(room_id, member).await? else {
        return Ok(());
    };
    let Some(room) = cr.room(room_id).await? else {
        cr.drop_pending_removal(room_id, member).await?;
        report.settled += 1;
        return Ok(());
    };
    let mut record = match cr.member(room_id, member).await? {
        Some(r) if r.state != MemberRecord::REMOVED => r,
        _ => {
            cr.drop_pending_removal(room_id, member).await?;
            report.settled += 1;
            return Ok(());
        }
    };

    let withdrawn = record.state == MemberRecord::OFFERED;
    let mut epoch = None;
    let mut withdrawn_at_host = false;
    // As an administrator's `members/remove/0.2` removes them (trust-tasks-tf #804): on
    // `open` and `attributed` rooms their credentials — an open offer's too — are withdrawn
    // at the host, and on a sealed tier the room advances past them.
    if !(withdrawn && room.visibility == "private") {
        if *vta_down {
            return Ok(());
        }
        let failed = match cr.key_holder() {
            None => {
                Some("this community has no link to the VTA that holds the room's keys".to_string())
            }
            Some(holder) => {
                let host = state
                    .config
                    .read()
                    .await
                    .vtc_did
                    .clone()
                    .unwrap_or_default();
                match remove_member(
                    &holder,
                    &room,
                    &host,
                    member,
                    withdrawn,
                    pending.cause.reason(),
                )
                .await
                {
                    Ok(r) => {
                        epoch = r.epoch;
                        withdrawn_at_host = r.revocation.is_some();
                        None
                    }
                    Err(HolderError::Unavailable(why)) => {
                        *vta_down = true;
                        Some(why)
                    }
                    Err(HolderError::Refused { code, message }) => {
                        Some(format!("the community's VTA refused: {code} {message}"))
                    }
                }
            }
        };
        if let Some(why) = failed {
            let mut next = pending;
            next.attempts = next.attempts.saturating_add(1);
            next.last_attempt_at = Some(rfc3339(now));
            next.next_attempt_at = rfc3339(now + backoff(next.attempts));
            next.last_error = Some(why.clone());
            cr.put_pending_removal(&next).await?;
            tracing::warn!(
                room = %room_id,
                member,
                attempts = next.attempts,
                next = %next.next_attempt_at,
                error = %why,
                "a departing member's removal from a community room did not complete; retrying"
            );
            report.retrying += 1;
            return Ok(());
        }
    }

    record.state = MemberRecord::REMOVED.into();
    record.removed_at = Some(rfc3339(now));
    record.credentials = None;
    record.renewal = None;
    record.sources.clear();
    record.welcome = None;
    cr.settle_removal(&record).await?;
    drop(guard);
    report.removed += 1;

    let row = CommunityRoomChangedData {
        event: if withdrawn {
            "offerWithdrawn"
        } else {
            "memberRemoved"
        }
        .to_string(),
        room_id: room.room_id.clone(),
        visibility: room.visibility.clone(),
        member: Some(member.to_string()),
        actions: Vec::new(),
        epoch,
        note: (!withdrawn || withdrawn_at_host)
            .then(|| removal_notice(withdrawn_at_host).to_string()),
        reason: Some(pending.cause.reason().to_string()),
        details: Vec::new(),
    };
    if let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer
            .write(ACTOR, Some(member), AuditEvent::CommunityRoomChanged(row))
            .await
    {
        tracing::warn!(error = %e, room = %room_id, "could not audit a departing member's removal");
    }
    tracing::info!(room = %room_id, member, ?epoch, withdrawn, "departing member removed from a community room");
    Ok(())
}

/// One pass: find unrecorded departures, then drive what is owed.
pub async fn run_once(state: &AppState, now: DateTime<Utc>) -> Result<DriveReport, AppError> {
    reconcile(state, now).await?;
    drive(state, now).await
}

/// The removals owed in `rooms`, as administrators read them under
/// `ext["org.openvtc"].departureRemovals` — the caller merges it into that object beside
/// whatever else it carries — or `None` when none is owed.
pub async fn ext_for(state: &AppState, rooms: &[&str]) -> Result<Option<Value>, AppError> {
    let mut owed = Vec::new();
    for room in rooms {
        for p in state.community_rooms.pending_removals_in(room).await? {
            owed.push(p.wire());
        }
    }
    Ok((!owed.is_empty()).then_some(Value::Array(owed)))
}

/// Run the worker until shutdown: a pass at start (resuming whatever a restart interrupted),
/// then whenever a departure is recorded, and every [`SWEEP_INTERVAL`] for the retries and
/// expiries that nothing announces.
pub fn spawn(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_once(&state, Utc::now()).await {
                tracing::warn!(error = %e, "community-room departure sweep failed");
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = super::community::departure_hinted() => {}
                _ = tokio::time::sleep(SWEEP_INTERVAL) => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_an_hour() {
        assert_eq!(backoff(1), chrono::Duration::seconds(30));
        assert_eq!(backoff(2), chrono::Duration::seconds(60));
        assert_eq!(backoff(3), chrono::Duration::seconds(120));
        assert_eq!(backoff(8), chrono::Duration::seconds(3600));
        assert_eq!(backoff(u32::MAX), chrono::Duration::seconds(3600));
    }
}
