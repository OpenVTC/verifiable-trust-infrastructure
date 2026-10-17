//! The profile of every room the community owns — its label and description, written
//! **into the room** by the community's VTA, so the room's members can read what the room
//! is (`vtc/rooms/community/create/0.3` step 5, `vtc/rooms/community/update/0.2` items
//! 10–12, `rooms/keys/profile/write/0.1`).
//!
//! # What goes where
//!
//! The label becomes the profile's `name`, the description its `description`, and nothing
//! else of the owner's record: **tags never** (they are administrators' filing). They reach
//! the community's own VTA in `rooms/keys/profile/write`, which signs them as the community,
//! seals them under the room's current epoch and stores them at this host — where, on a
//! sealed tier, they are one more opaque record. They never go into the room's host record,
//! a credential, `rooms/owner/register` or any other `rooms/*` task.
//!
//! A write replaces the whole profile, so the members it does not manage — `tags`, `emoji`,
//! `ext`, which a member holding `curate` may have set in the room — are first read back
//! (`rooms/keys/profile/read`) and carried over (update item 10).
//!
//! # Never the request's to fail
//!
//! A room with no profile yet is a complete room: create and update answer `written` only
//! when the VTA answered `written`, and otherwise `pending`, and the room and the change to
//! the owner's record stand either way. A pending profile is kept here
//! (`room-profile:<room>`, beside the owner's record in the `community_rooms` keyspace,
//! never inside it) and retried by [`sweep`] — **the one retry owner** — one attempt per due
//! room per pass, a capped exponential backoff with jitter (1 minute doubling to 6 hours)
//! after each failure. What is written is always the room's label and description **as
//! they are at the attempt**, so a later update supersedes a pending one by construction.
//! A lapsed room refuses the write until it is renewed; the room stays pending and is
//! written after the renewal (update item 11).
//!
//! # Crash-safe
//!
//! The record is written `pending` before the VTA is asked, and `written` only after it
//! answered. A process that dies between finds it pending on the next pass and writes it
//! again — the same profile under the same epoch, which converges.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::rooms::keys::profile::{
    read::v0_1 as profile_read, write::v0_1 as profile_write,
};
use vti_common::error::AppError;

use super::community::{CommunityRooms, HolderError, KeyHolder, OwnedRoom};
use crate::server::AppState;

/// How long one profile write may take at the VTA. Longer than a signature: the VTA reads
/// the room's head from this host, seals and stores the record here, each a call back.
pub const PROFILE_TIMEOUT: Duration = Duration::from_secs(60);

const TICK: Duration = Duration::from_secs(60);
const FIRST_PASS: Duration = Duration::from_secs(90);
const RETRY_BASE: Duration = Duration::from_secs(60);
const RETRY_CAP: Duration = Duration::from_secs(6 * 60 * 60);

const PROFILE_READ: &str = <profile_read::Payload as Payload>::TYPE_URI;
const PROFILE_WRITE: &str = <profile_write::Payload as Payload>::TYPE_URI;

/// The `ext` namespace in which a request to the VTA names the member it acts as — the
/// community's own DID, whatever else the VTA holds for the caller in the room.
const MEMBER_EXT: &str = "org.openvtc.rooms";

fn record_key(room_id: &str) -> Vec<u8> {
    format!("room-profile:{room_id}").into_bytes()
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `roomProfile` in create 0.3's and update 0.2's response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileOutcome {
    /// The VTA answered `written`.
    Written,
    /// Not written yet; the sweeper keeps trying.
    Pending,
    /// Nothing needed writing (update only).
    Unchanged,
}

impl ProfileOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Pending => "pending",
            Self::Unchanged => "unchanged",
        }
    }
}

/// What this community knows about one room's profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRecord {
    pub room_id: String,
    /// Whether the room's current label and description still have to be written.
    #[serde(default)]
    pub pending: bool,
    /// The name and description the VTA last answered `written` for, and when. Absent: the
    /// community has never written the room's profile (a room made before create 0.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_at: Option<String>,
    /// Failures since the last success.
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ProfileRecord {
    fn new(room_id: &str) -> Self {
        Self {
            room_id: room_id.to_string(),
            ..Default::default()
        }
    }

    /// Whether the community has ever written this room's profile.
    pub fn ever_written(&self) -> bool {
        self.written_at.is_some()
    }

    /// What the console is shown, in `ext["org.openvtc"].roomProfile`: `written`,
    /// `pending` (with the retry state) or `none` (never written, nothing pending).
    pub fn status(&self) -> Value {
        let state = if self.pending {
            "pending"
        } else if self.ever_written() {
            "written"
        } else {
            "none"
        };
        let mut v = json!({ "state": state });
        if self.attempts > 0 {
            v["attempts"] = json!(self.attempts);
        }
        for (name, field) in [
            ("writtenAt", &self.written_at),
            ("lastAttemptAt", &self.last_attempt_at),
            ("nextAttemptAt", &self.next_attempt_at),
            ("lastError", &self.last_error),
        ] {
            if let Some(f) = field {
                v[name] = json!(f);
            }
        }
        v
    }
}

/// The profile record of `room_id`, if this community has one.
pub async fn record(
    rooms: &CommunityRooms,
    room_id: &str,
) -> Result<Option<ProfileRecord>, AppError> {
    rooms.keyspace().get(record_key(room_id)).await
}

async fn put_record(rooms: &CommunityRooms, rec: &ProfileRecord) -> Result<(), AppError> {
    rooms.keyspace().insert(record_key(&rec.room_id), rec).await
}

/// `ext["org.openvtc"].roomProfile` for one room's `get`.
pub async fn room_ext(state: &AppState, room_id: &str) -> Result<Value, AppError> {
    Ok(record(&state.community_rooms, room_id)
        .await?
        .unwrap_or_else(|| ProfileRecord::new(room_id))
        .status())
}

/// `ext["org.openvtc"].roomProfile` for a `list` page, by room DID.
pub async fn list_ext(state: &AppState, room_ids: &[String]) -> Result<Value, AppError> {
    let mut rooms = serde_json::Map::new();
    for id in room_ids {
        let status = record(&state.community_rooms, id)
            .await?
            .unwrap_or_else(|| ProfileRecord::new(id))
            .status();
        rooms.insert(id.clone(), status);
    }
    Ok(Value::Object(rooms))
}

/// Whether an update must write the profile (update 0.2 item 10): the label or description
/// changed, the community has never written it (a room made before create 0.3), or an
/// earlier write is still pending.
pub async fn update_needs_write(
    state: &AppState,
    room_id: &str,
    label_or_description_changed: bool,
) -> Result<bool, AppError> {
    if label_or_description_changed {
        return Ok(true);
    }
    let rec = record(&state.community_rooms, room_id).await?;
    Ok(rec.is_none_or(|r| r.pending || !r.ever_written()))
}

/// Write `room`'s profile now — one attempt — and record what happened. `Pending` on any
/// failure, which the sweeper then owns. Never an error for the caller's request: a store
/// failure is logged and answered `pending`.
pub async fn write_now(state: &AppState, room: &OwnedRoom, now: DateTime<Utc>) -> ProfileOutcome {
    match attempt(state, room, now).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(room = %room.room_id, error = %e,
                "could not record a community room's profile state; the sweeper retries it");
            ProfileOutcome::Pending
        }
    }
}

/// One attempt, recorded: `pending` before the VTA is asked, `written` only after.
async fn attempt(
    state: &AppState,
    room: &OwnedRoom,
    now: DateTime<Utc>,
) -> Result<ProfileOutcome, AppError> {
    let mut rec = record(&state.community_rooms, &room.room_id)
        .await?
        .unwrap_or_else(|| ProfileRecord::new(&room.room_id));
    rec.pending = true;
    rec.last_attempt_at = Some(rfc3339(now));
    put_record(&state.community_rooms, &rec).await?;

    let vtc_did = state.config.read().await.vtc_did.clone();
    let result = match (state.community_rooms.key_holder(), vtc_did) {
        (Some(holder), Some(vtc_did)) => write_at_vta(&holder, &vtc_did, room).await,
        (None, _) => Err("this community has no VTA link to write the profile with".to_string()),
        (_, None) => Err("this community has no DID".to_string()),
    };
    match result {
        Ok(()) => {
            rec.pending = false;
            rec.written_name = Some(room.label.clone());
            rec.written_description = room.description.clone();
            rec.written_at = Some(rfc3339(now));
            rec.attempts = 0;
            rec.next_attempt_at = None;
            rec.last_error = None;
            put_record(&state.community_rooms, &rec).await?;
            tracing::info!(room = %room.room_id, "wrote a community room's profile into the room");
            Ok(ProfileOutcome::Written)
        }
        Err(why) => {
            rec.attempts = rec.attempts.saturating_add(1);
            rec.next_attempt_at = Some(rfc3339(now + backoff(rec.attempts)));
            rec.last_error = Some(why.clone());
            put_record(&state.community_rooms, &rec).await?;
            tracing::warn!(room = %room.room_id, attempts = rec.attempts, error = %why,
                "could not write a community room's profile; will retry");
            Ok(ProfileOutcome::Pending)
        }
    }
}

/// The profile write at the community's VTA, as the community: read the current profile,
/// carry over what the community does not manage, write the label and description.
async fn write_at_vta(holder: &KeyHolder, vtc_did: &str, room: &OwnedRoom) -> Result<(), String> {
    let as_community = json!({ MEMBER_EXT: { "member": vtc_did } });

    // Update item 10 SHOULD: tags, emoji and ext a curator set in the room are kept. A read
    // that fails is no reason not to write: the label is what the community owes its members.
    let mut profile = serde_json::Map::new();
    let read = holder
        .ask(
            PROFILE_READ,
            json!({ "roomId": room.room_id, "host": vtc_did, "ext": as_community }),
            PROFILE_TIMEOUT,
        )
        .await;
    match read {
        Ok(current) if current["status"] == "found" => {
            for carried in ["tags", "emoji", "ext"] {
                if let Some(v) = current["profile"].get(carried) {
                    profile.insert(carried.into(), v.clone());
                }
            }
        }
        Ok(_) => {}
        Err(e) => tracing::debug!(room = %room.room_id, error = %holder_error(&e),
            "could not read a community room's profile before re-writing it"),
    }
    profile.insert("name".into(), json!(room.label));
    if let Some(d) = &room.description {
        profile.insert("description".into(), json!(d));
    }

    let request: profile_write::Payload = serde_json::from_value(json!({
        "roomId": room.room_id,
        "host": vtc_did,
        "profile": profile,
        "ext": as_community,
    }))
    .map_err(|e| format!("the room's profile is not one the specification admits: {e}"))?;
    let answer = holder
        .ask(
            PROFILE_WRITE,
            serde_json::to_value(request).map_err(|e| e.to_string())?,
            PROFILE_TIMEOUT,
        )
        .await
        .map_err(|e| holder_error(&e))?;
    let answer: profile_write::Response = serde_json::from_value(answer).map_err(|e| {
        format!("the community's VTA answered rooms/keys/profile/write in a shape its specification does not define: {e}")
    })?;
    match answer.outcome {
        profile_write::ResponseOutcome::Written => Ok(()),
        other => Err(format!(
            "the community's VTA answered rooms/keys/profile/write with outcome `{other}`"
        )),
    }
}

fn holder_error(e: &HolderError) -> String {
    match e {
        HolderError::Unavailable(m) => format!("rooms/keys/profile/write: {m}"),
        HolderError::Refused { code, message } => {
            format!("rooms/keys/profile/write: the community's VTA refused: {code} {message}")
        }
    }
}

/// The wait after `attempts` consecutive failures: half the capped exponential ceiling,
/// plus up to the other half at random.
fn backoff(attempts: u32) -> chrono::Duration {
    use rand::RngExt as _;
    let factor = 1u32
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    let ceiling = RETRY_BASE.saturating_mul(factor).min(RETRY_CAP).as_secs();
    let half = ceiling / 2;
    let secs = half + rand::rng().random_range(0..=ceiling - half);
    chrono::Duration::seconds(secs as i64)
}

/// Run the sweeper until shutdown.
pub fn spawn(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut wait = FIRST_PASS;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            wait = TICK;
            if let Err(e) = sweep(&state, Utc::now()).await {
                tracing::warn!(error = %e, "community room profile pass failed");
            }
        }
    });
}

/// What a pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    pub written: Vec<String>,
    pub failed: Vec<String>,
}

/// One pass at `now`: write every pending profile that is due, for a room this community
/// still hosts and owns.
pub async fn sweep(state: &AppState, now: DateTime<Utc>) -> Result<SweepReport, AppError> {
    let mut report = SweepReport::default();
    let vtc_did = state.config.read().await.vtc_did.clone();
    let Some(vtc_did) = vtc_did else {
        return Ok(report);
    };
    if state.community_rooms.key_holder().is_none() {
        return Ok(report);
    }
    for room in state.community_rooms.rooms().await? {
        let Some(rec) = record(&state.community_rooms, &room.room_id).await? else {
            continue;
        };
        if !rec.pending
            || rec
                .next_attempt_at
                .as_deref()
                .and_then(parse_time)
                .is_some_and(|next| next > now)
        {
            continue;
        }
        if !still_ours(state, &room, &vtc_did).await {
            continue;
        }
        match attempt(state, &room, now).await? {
            ProfileOutcome::Written => report.written.push(room.room_id.clone()),
            _ => report.failed.push(room.room_id.clone()),
        }
    }
    Ok(report)
}

/// Whether `room` is still one this community hosts and owns.
async fn still_ours(state: &AppState, room: &OwnedRoom, vtc_did: &str) -> bool {
    match vti_rooms::storage::get_room(&state.rooms_ks, &room.room_id).await {
        Ok(hosted) => hosted.owner_did == vtc_did,
        Err(AppError::NotFound(_)) => false,
        Err(e) => {
            tracing::warn!(room = %room.room_id, error = %e,
                "could not read a community room; not writing its profile now");
            false
        }
    }
}
