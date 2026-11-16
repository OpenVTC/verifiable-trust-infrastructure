//! A room the community owns, archived and removed — `vtc/rooms/community/{archive,
//! unarchive,remove,removal/cancel}/0.1` (trust-tasks-tf `vtc/_shared/0.5/community-room`).
//!
//! # The owner's lifecycle, beside the host's
//!
//! A hosted room already has a lifecycle — `live`, `lapsed`, `dormant`, `reclaimable` — and
//! it is **computed** from the room's epoch, never set ([`vti_rooms::lifecycle`]): the host
//! never decides. This one is the other kind. It is the **owner's** decision, made by an
//! administrator and stored in the owner's record ([`OwnerStatus`] on [`OwnedRoom`]):
//!
//! ```text
//!   active ──archive──▶ archived(readOnly | noAccess) ──remove──▶ removalScheduled ──purgeAt──▶ purging ──▶ removed
//!     ▲                    │    ▲                                     │
//!     └────unarchive───────┘    └─────────── removal/cancel ──────────┘
//! ```
//!
//! - **archived, `readOnly`** — this community, as the room's host, refuses every task but a
//!   read (`vti_rooms::Room::frozen_at`); open offers are withdrawn; members keep reading.
//! - **archived, `noAccess`** — the room is **reset**: one revocation list withdrawing every
//!   credential it issued, from everyone (`rooms/owner/revoke`, a `room` withdrawal), the
//!   only withdrawal a `private` room's host can apply. Admitted members become
//!   `suspended`. A reset withdraws the community's own credentials too, so the VTA
//!   re-issues them before anything is recorded.
//! - **removalScheduled** — `noAccess`, with a date the content is purged; cancellable.
//! - **purging** — the content is being deleted at the host and every storage config.
//!   Not reversible.
//! - **removed** — a tombstone: the owner's record, the members' records without
//!   credentials, and a snapshot of the host record as it last stood.
//!
//! # Remote first, and resumable
//!
//! Every step at the VTA comes before the local record says it happened (R2.1). A reset is
//! the one step whose effect outlives a failure after it: the host may already refuse every
//! credential while the community's own re-issue has not landed. That is recorded as a
//! [`Pending`] change **before** the reset is asked for, and the worker here finishes it —
//! re-asking for the reset only while its outcome is unknown, never once the host accepted
//! one. A repeated request finishes it too, under the same lock.
//!
//! # One worker
//!
//! [`spawn`] is the one retry owner for what these transitions leave to do in the
//! background: finishing a pending change, starting a purge whose grace period ended,
//! purging, and restoring suspended members once a room leaves `noAccess`.

use std::time::Duration;

use chrono::{DateTime, Timelike as _, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use vtc_audit::{AuditEvent, CommunityRoomChangedData};
use vti_common::error::AppError;

use super::community::{CommunityRooms, HolderError, MemberRecord, OwnedRoom};
use crate::server::AppState;

/// The audit actor of a step the community takes by itself: a purge whose grace period
/// ended, a pending change finished, a member restored.
pub const ACTOR: &str = "vtc:room-lifecycle";

/// The grace period of a removal when neither the request nor `[rooms.community]` names
/// one, in days.
pub const DEFAULT_REMOVAL_GRACE_DAYS: u32 = 30;

/// The longest grace period a removal may ask for, in days (`remove/0.1` `graceDays`).
pub const MAX_REMOVAL_GRACE_DAYS: u32 = 365;

/// How often the worker looks for due work that nothing announces.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

const BACKOFF_BASE_SECS: i64 = 30;
const BACKOFF_CAP_SECS: i64 = 60 * 60;

/// Where a room stands in its owner's lifecycle (`RoomState`).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RoomState {
    #[default]
    Active,
    Archived,
    RemovalScheduled,
    Purging,
    Removed,
}

impl RoomState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::RemovalScheduled => "removalScheduled",
            Self::Purging => "purging",
            Self::Removed => "removed",
        }
    }

    /// Whether every credential the room issued is withdrawn and none will be restored: a
    /// room on its way out, or gone.
    pub fn withdrew_everyone_for_good(self) -> bool {
        matches!(self, Self::RemovalScheduled | Self::Purging | Self::Removed)
    }

    /// Whether the room's content is gone or going: nothing but its record remains to act on.
    pub fn purged_or_purging(self) -> bool {
        matches!(self, Self::Purging | Self::Removed)
    }
}

/// What an archived room's members may still do (`ArchiveAccess`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Access {
    ReadOnly,
    NoAccess,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "readOnly",
            Self::NoAccess => "noAccess",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "readOnly" => Some(Self::ReadOnly),
            "noAccess" => Some(Self::NoAccess),
            _ => None,
        }
    }
}

/// Attempts at a step the worker retries, and how the last went (`PurgeProgress`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl Progress {
    fn due(&self, now: DateTime<Utc>) -> bool {
        self.next_attempt_at
            .as_deref()
            .and_then(parse_time)
            .is_none_or(|next| next <= now)
    }

    fn failed(&mut self, now: DateTime<Utc>, why: String) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt_at = Some(rfc3339(now));
        self.next_attempt_at = Some(rfc3339(now + backoff(self.attempts)));
        self.last_error = Some(bounded(&why, 500));
    }

    /// The `PurgeProgress` of `vtc/_shared/0.5/community-room`.
    pub fn wire(&self) -> Value {
        let mut v = json!({ "attempts": self.attempts });
        if let Some(a) = &self.last_attempt_at {
            v["lastAttemptAt"] = json!(a);
        }
        if let Some(a) = &self.next_attempt_at {
            v["nextAttemptAt"] = json!(a);
        }
        if let Some(e) = &self.last_error {
            v["lastError"] = json!(e);
        }
        v
    }
}

/// A change of state begun and not finished (`PendingChange`): recorded before the VTA is
/// asked to reset the room, so a failure after the host accepted the reset is finished
/// rather than forgotten.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    /// The state the change leads to: `archived` (with `noAccess`), `removalScheduled` or
    /// `purging` (a removal without a grace period).
    pub state: RoomState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    pub began_at: String,
    /// The administrator who asked, recorded as `changedBy` when it finishes.
    pub requested_by: String,
    pub reason: String,
    /// For a removal: when the purge is due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_at: Option<String>,
    /// Once the host accepted the reset: its `revokedAt`, and the list's head. While absent
    /// the reset's outcome is unknown, and asking for it again is safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Value>,
    #[serde(default)]
    pub progress: Progress,
}

/// A room's state in its owner's lifecycle, as the owner records it (`RoomStatus`).
/// The default — every room stored before archival existed — is `active`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerStatus {
    #[serde(default)]
    pub state: RoomState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_at: Option<String>,
    /// While `purging`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge: Option<Progress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// Failures restoring suspended members, while they fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<Progress>,
    /// What became of the room's DID at the VTA when it was purged: a step that does not
    /// hold the purge (`remove/0.1`), so it is reported rather than retried forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_retirement: Option<String>,
}

impl OwnerStatus {
    pub fn is_initial(&self) -> bool {
        *self == Self::default()
    }

    /// Whether the room's members' credentials are withdrawn at its host — every member is
    /// `suspended`, and none is restored while it stays so.
    pub fn closed_to_members(&self) -> bool {
        self.state.withdrew_everyone_for_good() || self.access == Some(Access::NoAccess)
    }

    /// Whether the room admits, renews and restores: open, or archived `readOnly`.
    pub fn restores_members(&self) -> bool {
        matches!(self.state, RoomState::Active | RoomState::Archived) && !self.closed_to_members()
    }

    /// The `RoomStatus` of `vtc/_shared/0.5/community-room`; `restoring` is the count of
    /// suspended admissions the room owes a restore.
    pub fn wire(&self, restoring: u64) -> Value {
        let mut v = json!({ "state": self.state.as_str() });
        if matches!(
            self.state,
            RoomState::Archived | RoomState::RemovalScheduled
        ) {
            v["access"] = json!(self.access.unwrap_or(Access::NoAccess).as_str());
        }
        if let (Some(at), Some(by)) = (&self.changed_at, &self.changed_by) {
            v["changedAt"] = json!(at);
            v["changedBy"] = json!(by);
        }
        if let Some(at) = &self.purge_at
            && self.state != RoomState::Active
            && self.state != RoomState::Archived
        {
            v["purgeAt"] = json!(at);
        }
        if self.state == RoomState::Purging {
            v["purge"] = self.purge.clone().unwrap_or_default().wire();
        }
        if self.state == RoomState::Removed
            && let Some(at) = &self.removed_at
        {
            v["removedAt"] = json!(at);
        }
        if let Some(p) = &self.pending {
            let mut c = json!({ "state": p.state.as_str(), "beganAt": p.began_at });
            if let Some(a) = p.access {
                c["access"] = json!(a.as_str());
            }
            if let Some(e) = &p.progress.last_error {
                c["lastError"] = json!(e);
            }
            v["pendingChange"] = c;
        }
        if restoring > 0 && self.restores_members() {
            v["restoring"] = json!(restoring);
        }
        v
    }

    /// What the console is shown that `RoomStatus` has no member for, under
    /// `ext["org.openvtc"].lifecycle`: a failing restore, the reset a pending change is
    /// waiting on, and what became of the room's DID.
    pub fn ext(&self) -> Option<Value> {
        let mut v = serde_json::Map::new();
        if let Some(r) = &self.restore {
            v.insert("restore".into(), r.wire());
        }
        if let Some(p) = &self.pending {
            v.insert("pendingChange".into(), p.progress.wire());
        }
        if let Some(d) = &self.did_retirement {
            v.insert("didRetirement".into(), json!(d));
        }
        (!v.is_empty()).then_some(Value::Object(v))
    }
}

/// Why a transition did not happen.
#[derive(Debug)]
pub enum Refusal {
    /// The room is not in a state this transition starts from.
    WrongState(RoomState),
    /// The community's VTA, or the host behind it, did not do what was asked. With a
    /// [`Pending`] recorded, the worker finishes the change.
    Holder(HolderError),
    Internal(AppError),
}

impl From<AppError> for Refusal {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// What a transition did.
#[derive(Debug, Default)]
pub struct Outcome {
    pub room: Option<OwnedRoom>,
    pub changed: bool,
    pub withdrawn_offers: u64,
    /// The revocation list's head the host accepted, and its `revokedAt`.
    pub revocation: Option<(Value, String)>,
}

// ─── the transitions ─────────────────────────────────────────────────────

/// `vtc/rooms/community/archive/0.1`: archive `room_id` with `access`, or move an archived
/// room to the other access. Held under the community's room lock throughout.
pub async fn archive(
    state: &AppState,
    room_id: &str,
    access: Access,
    actor: &str,
    reason: &str,
) -> Result<Outcome, Refusal> {
    let cr = &*state.community_rooms;
    let _guard = cr.lock().await;
    let room = finish_pending_locked(state, room_id).await?;
    let from = room.status.clone();
    match from.state {
        RoomState::Active | RoomState::Archived => {}
        other => return Err(Refusal::WrongState(other)),
    }
    if from.state == RoomState::Archived && from.access == Some(access) {
        return Ok(Outcome {
            room: Some(room),
            ..Default::default()
        });
    }
    let now = Utc::now();
    let offers: Vec<MemberRecord> = cr
        .members(room_id)
        .await?
        .into_iter()
        .filter(|m| m.state == MemberRecord::OFFERED)
        .collect();

    match access {
        Access::NoAccess => {
            // A reset withdraws the offers' credentials with everyone else's; `close`
            // records and audits the change once the community holds fresh credentials.
            reset_and_close(
                state,
                room,
                Pending {
                    state: RoomState::Archived,
                    access: Some(Access::NoAccess),
                    began_at: rfc3339(now),
                    requested_by: actor.to_string(),
                    reason: reason.to_string(),
                    purge_at: None,
                    revoked_at: None,
                    revocation: None,
                    progress: Progress::default(),
                },
            )
            .await
        }
        Access::ReadOnly => {
            let mut revocation = None;
            if from.state == RoomState::Active && !offers.is_empty() && room.visibility != "private"
            {
                // The offers' credentials, withdrawn at the host before anything is recorded
                // (archive item 4). A private room's host cannot be told whom to refuse.
                let holder = holder(cr)?;
                let withdraw: Vec<Value> = offers
                    .iter()
                    .map(|o| json!({ "kind": "subject", "subject": o.member }))
                    .collect();
                let answer = super::departures::revoke_at_host(
                    &holder,
                    &room,
                    &host(state).await,
                    Value::Array(withdraw),
                    reason,
                )
                .await
                .map_err(Refusal::Holder)?;
                let at = super::departures::latest_revoked_at(&answer, |e| e["kind"] == "subject");
                revocation = Some((answer["head"].clone(), at));
            }
            set_frozen(state, room_id, true).await?;
            let now = Utc::now();
            for mut o in offers.iter().cloned() {
                withdraw_offer(&mut o, now);
                cr.settle_removal(&o).await?;
            }
            let mut room = room;
            room.status = OwnerStatus {
                state: RoomState::Archived,
                access: Some(Access::ReadOnly),
                changed_at: Some(rfc3339(now)),
                changed_by: Some(actor.to_string()),
                ..Default::default()
            };
            put_room(state, &room).await?;
            let mut row = crate::trust_tasks::community_room_tasks::change("archived", &room);
            row.note = Some(format!(
                "readOnly (was {}); {} offer(s) withdrawn",
                describe(&from),
                offers.len()
            ));
            row.reason = Some(reason.to_string());
            audit(state, actor, row).await;
            hint();
            Ok(Outcome {
                room: Some(room),
                changed: true,
                withdrawn_offers: offers.len() as u64,
                revocation,
            })
        }
    }
}

/// `vtc/rooms/community/unarchive/0.1`: an archived room becomes active again. Suspended
/// members are restored by the worker.
pub async fn unarchive(
    state: &AppState,
    room_id: &str,
    actor: &str,
    reason: &str,
) -> Result<Outcome, Refusal> {
    let cr = &*state.community_rooms;
    let _guard = cr.lock().await;
    let mut room = finish_pending_locked(state, room_id).await?;
    if room.status.state != RoomState::Archived {
        return Err(Refusal::WrongState(room.status.state));
    }
    let from = room.status.clone();
    set_frozen(state, room_id, false).await?;
    let now = Utc::now();
    room.status = OwnerStatus {
        state: RoomState::Active,
        changed_at: Some(rfc3339(now)),
        changed_by: Some(actor.to_string()),
        ..Default::default()
    };
    put_room(state, &room).await?;
    let mut row = crate::trust_tasks::community_room_tasks::change("unarchived", &room);
    row.note = Some(format!("was {}", describe(&from)));
    row.reason = Some(reason.to_string());
    audit(state, actor, row).await;
    // A profile write owed is resumed by its own sweeper's next pass; suspended members
    // by this worker.
    hint();
    Ok(Outcome {
        room: Some(room),
        changed: true,
        ..Default::default()
    })
}

/// `vtc/rooms/community/remove/0.1`: schedule an archived room's purge `grace` from now —
/// at once when `grace` is zero — resetting it first when it is still `readOnly`. A room
/// already scheduled is rescheduled from now.
pub async fn remove(
    state: &AppState,
    room_id: &str,
    grace: chrono::Duration,
    actor: &str,
    reason: &str,
) -> Result<Outcome, Refusal> {
    let cr = &*state.community_rooms;
    let _guard = cr.lock().await;
    let room = finish_pending_locked(state, room_id).await?;
    let from = room.status.clone();
    match from.state {
        RoomState::Archived | RoomState::RemovalScheduled => {}
        other => return Err(Refusal::WrongState(other)),
    }
    let now = Utc::now();
    let purge_at = now + grace;
    let target = if grace <= chrono::Duration::zero() {
        RoomState::Purging
    } else {
        RoomState::RemovalScheduled
    };
    let pending = Pending {
        state: target,
        access: Some(Access::NoAccess),
        began_at: rfc3339(now),
        requested_by: actor.to_string(),
        reason: reason.to_string(),
        purge_at: Some(rfc3339(purge_at)),
        revoked_at: None,
        revocation: None,
        progress: Progress::default(),
    };
    let out = if from.closed_to_members() {
        // Already reset: nothing to ask the VTA.
        close(state, room, pending, Utc::now()).await?
    } else {
        reset_and_close(state, room, pending).await?
    };
    hint();
    Ok(out)
}

/// `vtc/rooms/community/removal/cancel/0.1`: a scheduled removal is called off, and the
/// room stays archived with `noAccess`.
pub async fn cancel_removal(
    state: &AppState,
    room_id: &str,
    actor: &str,
    reason: &str,
) -> Result<Outcome, Refusal> {
    let cr = &*state.community_rooms;
    let _guard = cr.lock().await;
    let mut room = finish_pending_locked(state, room_id).await?;
    if room.status.state != RoomState::RemovalScheduled {
        return Err(Refusal::WrongState(room.status.state));
    }
    let was = room.status.purge_at.clone().unwrap_or_default();
    room.status = OwnerStatus {
        state: RoomState::Archived,
        access: Some(Access::NoAccess),
        changed_at: Some(rfc3339(Utc::now())),
        changed_by: Some(actor.to_string()),
        ..Default::default()
    };
    put_room(state, &room).await?;
    let mut row = crate::trust_tasks::community_room_tasks::change("removalCancelled", &room);
    row.note = Some(format!("the purge was due at {was}"));
    row.reason = Some(reason.to_string());
    audit(state, actor, row).await;
    Ok(Outcome {
        room: Some(room),
        changed: true,
        ..Default::default()
    })
}

// ─── reset, and closing a room ───────────────────────────────────────────

/// Record `pending`, reset the room at its host, re-issue the community's own credentials,
/// and close the room into `pending.state`. A step that fails leaves `pending` for the
/// worker; a reset the VTA refused outright leaves nothing.
async fn reset_and_close(
    state: &AppState,
    mut room: OwnedRoom,
    pending: Pending,
) -> Result<Outcome, Refusal> {
    room.status.pending = Some(pending);
    put_room(state, &room).await?;
    drive_pending(state, room).await
}

/// Take a recorded [`Pending`] as far as it goes. Called under the room lock.
async fn drive_pending(state: &AppState, mut room: OwnedRoom) -> Result<Outcome, Refusal> {
    let Some(mut pending) = room.status.pending.clone() else {
        return Ok(Outcome {
            room: Some(room),
            ..Default::default()
        });
    };
    let cr = &*state.community_rooms;
    let now = Utc::now();
    let holder = match cr.key_holder() {
        Some(h) => h,
        None => {
            let e = HolderError::Unavailable(
                "this community has no link to the VTA that holds the room's keys".into(),
            );
            return Err(record_failure(state, room, pending, e).await);
        }
    };

    if pending.revoked_at.is_none() {
        match super::departures::revoke_at_host(
            &holder,
            &room,
            &host(state).await,
            json!([{ "kind": "room" }]),
            &pending.reason,
        )
        .await
        {
            Ok(answer) => {
                pending.revoked_at = Some(super::departures::latest_revoked_at(&answer, |e| {
                    e["kind"] == "room"
                }));
                pending.revocation = Some(answer["head"].clone());
                room.status.pending = Some(pending.clone());
                put_room(state, &room).await?;
            }
            // Refused outright: the VTA signed nothing, so nothing is pending.
            Err(HolderError::Refused { code, message }) if pending.progress.attempts == 0 => {
                room.status.pending = None;
                put_room(state, &room).await?;
                return Err(Refusal::Holder(HolderError::Refused { code, message }));
            }
            Err(e) => return Err(record_failure(state, room, pending, e).await),
        }
    }

    // The re-issue must be later than the reset by the credential's own clock, whatever
    // precision either is written with: `validFrom` before `revokedAt` is withdrawn by it
    // (`rooms/revocations/put` *Matching*).
    let revoked_at = pending
        .revoked_at
        .as_deref()
        .and_then(parse_time)
        .unwrap_or(now);
    let after = revoked_at.with_nanosecond(0).unwrap_or(revoked_at) + chrono::Duration::seconds(1);
    if let Ok(wait) = (after - Utc::now()).to_std() {
        tokio::time::sleep(wait).await;
    }
    match super::community_renewal::reissue_after_reset(state, &holder, &room).await {
        Ok(until) => room.owner_authority_valid_until = until,
        Err(why) => {
            return Err(record_failure(state, room, pending, HolderError::Unavailable(why)).await);
        }
    }

    close(state, room, pending, Utc::now())
        .await
        .map_err(Refusal::from)
}

/// Close the room into `pending`'s state once its credentials are withdrawn: every admitted
/// member `suspended`, every open offer withdrawn, writes refused at the host, and — for a
/// removal without a grace period — the purge begun. Audited here, as `pending` asked for
/// it, whether the request or the worker got it this far.
async fn close(
    state: &AppState,
    mut room: OwnedRoom,
    pending: Pending,
    now: DateTime<Utc>,
) -> Result<Outcome, AppError> {
    let cr = &*state.community_rooms;
    let at = rfc3339(now);
    let from = room.status.clone();
    let (mut suspended, mut withdrawn) = (0u64, 0u64);
    for mut m in cr.members(&room.room_id).await? {
        if m.state == MemberRecord::ADMITTED {
            m.state = MemberRecord::SUSPENDED.into();
            m.suspended_at = Some(at.clone());
            // Credentials the reset withdrew are of no use to the member.
            m.renewal = None;
            m.welcome = None;
            cr.put_member(&m).await?;
            suspended += 1;
        } else if m.state == MemberRecord::OFFERED {
            withdraw_offer(&mut m, now);
            cr.settle_removal(&m).await?;
            withdrawn += 1;
        }
    }
    set_frozen(state, &room.room_id, true).await?;
    let mut status = OwnerStatus {
        state: pending.state,
        access: Some(Access::NoAccess),
        changed_at: Some(at.clone()),
        changed_by: Some(pending.requested_by.clone()),
        purge_at: pending.purge_at.clone(),
        ..Default::default()
    };
    if status.state == RoomState::Purging {
        status.purge = Some(Progress::default());
        room.hosted_snapshot = snapshot(state, &room.room_id).await?;
    }
    room.status = status;
    put_room(state, &room).await?;

    let event = match pending.state {
        RoomState::Archived => "archived",
        RoomState::Purging => "removedNow",
        _ => "removalScheduled",
    };
    let mut row = crate::trust_tasks::community_room_tasks::change(event, &room);
    let mut note = format!(
        "noAccess (was {}); {suspended} member(s) suspended, {withdrawn} offer(s) withdrawn",
        describe(&from)
    );
    if let Some(at) = &pending.purge_at {
        note.push_str(&format!("; purge at {at}"));
    }
    if let Some(r) = &pending.revoked_at {
        note.push_str(&format!("; credentials reset at {r}"));
    }
    row.note = Some(note);
    row.reason = Some(pending.reason.clone());
    audit(state, &pending.requested_by, row).await;
    hint();
    Ok(Outcome {
        room: Some(room),
        changed: true,
        withdrawn_offers: withdrawn,
        revocation: pending.revocation.clone().zip(pending.revoked_at.clone()),
    })
}

async fn record_failure(
    state: &AppState,
    mut room: OwnedRoom,
    mut pending: Pending,
    e: HolderError,
) -> Refusal {
    let why = match &e {
        HolderError::Unavailable(m) => m.clone(),
        HolderError::Refused { code, message } => {
            format!("the community's VTA refused: {code} {message}")
        }
    };
    pending.progress.failed(Utc::now(), why.clone());
    room.status.pending = Some(pending);
    if let Err(e) = put_room(state, &room).await {
        return Refusal::Internal(e);
    }
    tracing::warn!(room = %room.room_id, error = %why,
        "a community room's change of state did not finish; the community finishes it");
    hint();
    Refusal::Holder(e)
}

/// The room, with any pending change finished first. Under the room lock.
async fn finish_pending_locked(state: &AppState, room_id: &str) -> Result<OwnedRoom, Refusal> {
    let Some(room) = state.community_rooms.room(room_id).await? else {
        return Err(Refusal::Internal(AppError::NotFound(format!(
            "this community owns no room `{room_id}`"
        ))));
    };
    if room.status.pending.is_none() {
        return Ok(room);
    }
    let out = drive_pending(state, room).await?;
    Ok(out.room.expect("driven"))
}

// ─── the worker ──────────────────────────────────────────────────────────

static WORK: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Wake the worker.
pub fn hint() {
    WORK.notify_one();
}

/// What a pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub finished: Vec<String>,
    pub purges_started: Vec<String>,
    pub removed: Vec<String>,
    pub restored: u64,
    pub failed: Vec<String>,
}

/// Run the worker until shutdown: a pass at start, on every [`hint`], and every
/// [`SWEEP_INTERVAL`].
pub fn spawn(
    state: AppState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_once(&state, Utc::now()).await {
                tracing::warn!(error = %e, "community room lifecycle pass failed");
            }
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = WORK.notified() => {}
                _ = tokio::time::sleep(SWEEP_INTERVAL) => {}
            }
        }
    })
}

/// One pass at `now`.
pub async fn run_once(state: &AppState, now: DateTime<Utc>) -> Result<Report, AppError> {
    let mut report = Report::default();
    let cr = &*state.community_rooms;
    for room in cr.rooms().await? {
        let id = room.room_id.clone();
        // A change begun and not finished.
        if let Some(p) = &room.status.pending {
            if !p.progress.due(now) {
                continue;
            }
            let _guard = cr.lock().await;
            let Some(room) = cr.room(&id).await? else {
                continue;
            };
            match drive_pending(state, room).await {
                Ok(_) => report.finished.push(id.clone()),
                Err(_) => report.failed.push(id.clone()),
            }
            continue;
        }
        match room.status.state {
            RoomState::RemovalScheduled
                if room
                    .status
                    .purge_at
                    .as_deref()
                    .and_then(parse_time)
                    .is_some_and(|at| at <= now) =>
            {
                begin_purge(state, &id, now).await?;
                report.purges_started.push(id.clone());
                // Purged in the same pass, below.
                if purge_pass(state, &id, now).await? {
                    report.removed.push(id);
                } else {
                    report.failed.push(id);
                }
            }
            RoomState::Purging if room.status.purge.clone().unwrap_or_default().due(now) => {
                if purge_pass(state, &id, now).await? {
                    report.removed.push(id);
                } else {
                    report.failed.push(id);
                }
            }
            _ if room.status.restores_members() => {
                let restore = room.status.restore.clone().unwrap_or_default();
                if restore.due(now) {
                    report.restored += restore_pass(state, &id, now).await?;
                }
            }
            _ => {}
        }
    }
    Ok(report)
}

async fn begin_purge(state: &AppState, room_id: &str, now: DateTime<Utc>) -> Result<(), AppError> {
    let cr = &*state.community_rooms;
    let _guard = cr.lock().await;
    let Some(mut room) = cr.room(room_id).await? else {
        return Ok(());
    };
    if room.status.state != RoomState::RemovalScheduled {
        return Ok(());
    }
    room.hosted_snapshot = snapshot(state, room_id).await?;
    room.status.state = RoomState::Purging;
    room.status.purge = Some(Progress::default());
    put_room(state, &room).await?;
    let mut row = crate::trust_tasks::community_room_tasks::change("purgeStarted", &room);
    row.note = Some(format!("grace period ended at {}", rfc3339(now)));
    audit(state, ACTOR, row).await;
    Ok(())
}

/// One purge pass over `room_id`. `Ok(true)` once the room is `removed`.
///
/// Every step is idempotent, so a pass interrupted anywhere is finished by the next. The
/// owner's tombstone is written last: until it says `removed`, the next pass purges again.
pub async fn purge_pass(
    state: &AppState,
    room_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let cr = &*state.community_rooms;
    let Some(room) = cr.room(room_id).await? else {
        return Ok(false);
    };
    if room.status.state != RoomState::Purging {
        return Ok(room.status.state == RoomState::Removed);
    }

    match purge_content(state, &room).await {
        Ok(()) => {}
        Err(why) => {
            let _guard = cr.lock().await;
            let Some(mut room) = cr.room(room_id).await? else {
                return Ok(false);
            };
            let mut p = room.status.purge.clone().unwrap_or_default();
            p.failed(now, why.clone());
            room.status.purge = Some(p);
            put_room(state, &room).await?;
            tracing::warn!(room = %room_id, error = %why,
                "a community room's purge did not finish; retrying");
            return Ok(false);
        }
    }

    // The room's identity. Not a step that holds the purge (`remove/0.1`): the VTA may refuse
    // a context it does not let this community administer, and a DID left at the VTA admits
    // nobody to a room that no longer exists anywhere.
    let did_note = retire_did(state, &room).await;

    let _guard = cr.lock().await;
    let Some(mut room) = cr.room(room_id).await? else {
        return Ok(false);
    };
    // The owner's side: credentials, Welcomes, renewals and owed removals go; the members'
    // records stay, with their states and dates, as the room's history.
    let at = rfc3339(now);
    for mut m in cr.members(room_id).await? {
        let removed = m.state != MemberRecord::REMOVED;
        m.credentials = None;
        m.welcome = None;
        m.renewal = None;
        m.sources.clear();
        if removed {
            m.state = MemberRecord::REMOVED.into();
            m.removed_at = Some(at.clone());
            m.suspended_at = None;
        }
        cr.settle_removal(&m).await?;
    }
    for p in cr.pending_removals_in(room_id).await? {
        cr.drop_pending_removal(&p.room_id, &p.member).await?;
    }
    cr.forget_room_state(room_id).await?;
    room.status.state = RoomState::Removed;
    room.status.removed_at = Some(at);
    room.status.purge = None;
    room.status.did_retirement = Some(did_note);
    put_room(state, &room).await?;
    let mut row = crate::trust_tasks::community_room_tasks::change("removed", &room);
    row.note = room.status.did_retirement.clone();
    audit(state, ACTOR, row).await;
    tracing::info!(room = %room_id, "a community room was purged and removed");
    Ok(true)
}

/// Delete everything the room's host holds for it: its files in every storage config, its
/// records, epochs, commits and revocation list, its storage assignment, the group room
/// bindings naming it, the log of a serverless identity — and last the host record.
async fn purge_content(state: &AppState, room: &OwnedRoom) -> Result<(), String> {
    let id = room.room_id.as_str();
    let files = state
        .room_files
        .purge_room(id)
        .await
        .map_err(|e| format!("the room's files: {e}"))?;
    if files.remaining > 0 {
        return Err(format!(
            "{} of the room's files could not be deleted from storage yet: {}",
            files.remaining,
            files.last_error.unwrap_or_default()
        ));
    }
    // Bindings first: a binding naming a room that is gone would offer it again.
    let ks = state.directory.ks();
    for b in crate::groups::bindings::all(ks)
        .await
        .map_err(|e| e.to_string())?
    {
        if b.room().is_some_and(|r| r.room_id == id) {
            crate::groups::bindings::delete(ks, &b.group_id, &b.binding_id)
                .await
                .map_err(|e| format!("a group binding naming the room: {e}"))?;
        }
    }
    state
        .room_storage
        .drop_assignment(id)
        .await
        .map_err(|e| format!("the room's storage assignment: {e}"))?;
    if let Some(path) = &room.did_path {
        state
            .community_rooms
            .remove_did_log(path)
            .await
            .map_err(|e| format!("the room's served DID log: {e}"))?;
    }
    vti_rooms::storage::purge_room_rows(
        &state.rooms_ks,
        &state.room_records_ks,
        &state.room_epoch_links_ks,
        &state.room_revocations_ks,
        id,
    )
    .await
    .map_err(|e| format!("the room's records: {e}"))?;
    crate::admin_events::notify(crate::admin_events::Topic::Rooms);
    Ok(())
}

/// Have the VTA delete the room's DID (`webvh/dids/delete/1.0`), and say how it went.
async fn retire_did(state: &AppState, room: &OwnedRoom) -> String {
    use vti_specs::vta::webvh::dids::delete::v1_0 as did_delete;
    let Some(holder) = state.community_rooms.key_holder() else {
        return "not retired: this community has no link to its VTA".into();
    };
    let payload = json!({ "did": room.room_id });
    let payload = match serde_json::from_value::<did_delete::Payload>(payload)
        .and_then(serde_json::to_value)
    {
        Ok(p) => p,
        Err(e) => return format!("not retired: {e}"),
    };
    match holder
        .ask(
            <did_delete::Payload as Payload>::TYPE_URI,
            payload,
            super::community::SIGN_TIMEOUT,
        )
        .await
    {
        Ok(_) => "retired: the VTA deleted the room's DID and its keys".into(),
        Err(HolderError::Refused { code, message }) => bounded(
            &format!("not retired: the VTA refused: {code} {message}"),
            500,
        ),
        Err(HolderError::Unavailable(m)) => bounded(&format!("not retired: {m}"), 500),
    }
}

/// Restore every suspended member of a room that no longer withholds them: fresh membership
/// and authority, the same actions and expiry, kept for the member to collect as a renewal
/// (`unarchive/0.1`). An admission whose expiry has passed is recorded removed instead.
async fn restore_pass(
    state: &AppState,
    room_id: &str,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let cr = &*state.community_rooms;
    let suspended: Vec<MemberRecord> = cr
        .members(room_id)
        .await?
        .into_iter()
        .filter(|m| m.state == MemberRecord::SUSPENDED)
        .collect();
    if suspended.is_empty() {
        return Ok(0);
    }
    let Some(holder) = cr.key_holder() else {
        return Ok(0);
    };
    let mut restored = 0;
    for m in suspended {
        let _guard = cr.lock().await;
        let Some(room) = cr.room(room_id).await? else {
            return Ok(restored);
        };
        if !room.status.restores_members() {
            return Ok(restored);
        }
        let Some(mut current) = cr.member(room_id, &m.member).await? else {
            continue;
        };
        if current.state != MemberRecord::SUSPENDED {
            continue;
        }
        let expired = parse_time(&current.valid_until).is_none_or(|until| until <= now);
        if expired {
            current.state = MemberRecord::REMOVED.into();
            current.removed_at = Some(rfc3339(now));
            current.suspended_at = None;
            cr.settle_removal(&current).await?;
            let mut row = crate::trust_tasks::community_room_tasks::change("memberRemoved", &room);
            row.member = Some(current.member.clone());
            row.note = Some("not restored: the admission expired while the room was closed".into());
            audit(state, ACTOR, row).await;
            continue;
        }
        let issued = crate::trust_tasks::community_room_tasks::issue_renewal(
            &holder,
            &room,
            &current.member,
            &current.actions,
            &current.valid_until,
        )
        .await;
        match issued {
            Ok((membership, authority)) => {
                current.renewal = Some(super::community::Renewal {
                    membership,
                    authority,
                    valid_until: current.valid_until.clone(),
                    renews: current.valid_until.clone(),
                    issued_at: rfc3339(now),
                });
                current.state = MemberRecord::ADMITTED.into();
                current.suspended_at = None;
                cr.put_member(&current).await?;
                let mut row =
                    crate::trust_tasks::community_room_tasks::change("memberRestored", &room);
                row.member = Some(current.member.clone());
                row.actions = current.actions.clone();
                audit(state, ACTOR, row).await;
                restored += 1;
            }
            Err(e) => {
                let mut room = room;
                let mut p = room.status.restore.clone().unwrap_or_default();
                p.failed(
                    now,
                    match e {
                        HolderError::Unavailable(m) => m,
                        HolderError::Refused { code, message } => {
                            format!("the community's VTA refused: {code} {message}")
                        }
                    },
                );
                room.status.restore = Some(p);
                put_room(state, &room).await?;
                return Ok(restored);
            }
        }
    }
    // Every one restored: a failure streak is over.
    let _guard = cr.lock().await;
    if let Some(mut room) = cr.room(room_id).await?
        && room.status.restore.is_some()
    {
        room.status.restore = None;
        put_room(state, &room).await?;
    }
    Ok(restored)
}

// ─── small things ────────────────────────────────────────────────────────

fn holder(cr: &CommunityRooms) -> Result<super::community::KeyHolder, Refusal> {
    cr.key_holder().ok_or_else(|| {
        Refusal::Holder(HolderError::Unavailable(
            "this community has no link to the VTA that holds the room's keys".into(),
        ))
    })
}

async fn host(state: &AppState) -> String {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default()
}

/// Write the owner's record of a room under the room lock, re-reading nothing: the caller
/// holds the lock and the current record. The details (label, description, tags) are the
/// record's own and are never written back stale, because `update` takes the same lock.
async fn put_room(state: &AppState, room: &OwnedRoom) -> Result<(), AppError> {
    let _g = state.community_rooms.record_lock().await;
    let mut current = state
        .community_rooms
        .room(&room.room_id)
        .await?
        .unwrap_or_else(|| room.clone());
    current.status = room.status.clone();
    current.owner_authority_valid_until = room.owner_authority_valid_until.clone();
    if room.hosted_snapshot.is_some() {
        current.hosted_snapshot = room.hosted_snapshot.clone();
    }
    state.community_rooms.put_room(&current).await
}

/// Refuse (or accept again) every task on the room but a read, as its host.
async fn set_frozen(state: &AppState, room_id: &str, frozen: bool) -> Result<(), AppError> {
    let at = frozen.then(|| Utc::now().timestamp().max(0) as u64);
    match vti_rooms::storage::set_frozen(&state.rooms_ks, room_id, at).await {
        Ok(()) | Err(AppError::NotFound(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The host record as it stands, as a purged room's reads keep showing it.
async fn snapshot(state: &AppState, room_id: &str) -> Result<Option<Value>, AppError> {
    match crate::routes::rooms::hosted_room(state, room_id).await {
        Ok(v) => Ok(Some(serde_json::to_value(v)?)),
        Err(AppError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn withdraw_offer(m: &mut MemberRecord, now: DateTime<Utc>) {
    m.state = MemberRecord::REMOVED.into();
    m.removed_at = Some(rfc3339(now));
    m.credentials = None;
    m.renewal = None;
    m.welcome = None;
}

fn describe(s: &OwnerStatus) -> String {
    match s.access {
        Some(a) if s.state == RoomState::Archived => format!("archived, {}", a.as_str()),
        _ => s.state.as_str().to_string(),
    }
}

async fn audit(state: &AppState, actor: &str, data: CommunityRoomChangedData) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let event = data.event.clone();
    if let Err(e) = writer
        .write(actor, None, AuditEvent::CommunityRoomChanged(data))
        .await
    {
        tracing::warn!(error = %e, %event, "could not audit a community room lifecycle change");
    }
}

/// The delay before the next attempt after `attempts` failures: 30 s doubling, at most an
/// hour — the departure worker's.
pub fn backoff(attempts: u32) -> chrono::Duration {
    let shift = attempts.saturating_sub(1).min(16);
    chrono::Duration::seconds((BACKOFF_BASE_SECS << shift).min(BACKOFF_CAP_SECS))
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn bounded(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_status_is_active() {
        let s: OwnerStatus = serde_json::from_value(json!({})).unwrap();
        assert_eq!(s.state, RoomState::Active);
        assert!(s.is_initial());
        assert!(s.restores_members());
        assert_eq!(s.wire(0), json!({ "state": "active" }));
    }

    #[test]
    fn no_access_withholds_members_and_read_only_does_not() {
        let ro = OwnerStatus {
            state: RoomState::Archived,
            access: Some(Access::ReadOnly),
            ..Default::default()
        };
        let na = OwnerStatus {
            access: Some(Access::NoAccess),
            ..ro.clone()
        };
        assert!(ro.restores_members() && !ro.closed_to_members());
        assert!(!na.restores_members() && na.closed_to_members());
        let scheduled = OwnerStatus {
            state: RoomState::RemovalScheduled,
            ..Default::default()
        };
        assert!(scheduled.closed_to_members());
        // A removal scheduled is always noAccess on the wire.
        assert_eq!(scheduled.wire(0)["access"], "noAccess");
    }

    #[test]
    fn restoring_is_shown_only_where_members_are_restored() {
        let active = OwnerStatus::default();
        assert_eq!(active.wire(3)["restoring"], 3);
        let na = OwnerStatus {
            state: RoomState::Archived,
            access: Some(Access::NoAccess),
            ..Default::default()
        };
        assert!(na.wire(3).get("restoring").is_none());
    }

    #[test]
    fn backoff_doubles_to_an_hour() {
        assert_eq!(backoff(1), chrono::Duration::seconds(30));
        assert_eq!(backoff(3), chrono::Duration::seconds(120));
        assert_eq!(backoff(40), chrono::Duration::seconds(3600));
    }
}
