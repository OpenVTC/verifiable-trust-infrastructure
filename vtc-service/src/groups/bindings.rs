//! What a group's members receive through it: its **bindings**
//! (`vtc/groups/bindings/{add,remove,list}`). Room bindings only, for now: a
//! grants or role binding is refused `kindNotServed` (bindings/add item 7)
//! until the community provisions resource grants from groups (P5).
//!
//! # A room binding
//!
//! Links a room the community owns to the group. Every active member of the
//! group is offered admission to the room, with the binding's `actions`, valid
//! `validFor` — through the same offer path an administrator's
//! `vtc/rooms/community/members/add` takes, so the member still accepts with
//! their own key package. Leaving the group removes them from the room unless
//! something else still covers them: another binding, or an administrator's
//! direct admission. Each room admission records what covers it
//! ([`MemberRecord::sources`]).
//!
//! # The reconciler
//!
//! [`reconcile`] is the one owner of every effect of a binding, run on a timer
//! and woken by every group membership or binding change ([`kick`]):
//!
//! - **Offers.** An active group member with no live admission to a bound room
//!   is offered one, issued by the room through the community's VTA and
//!   recorded only after the VTA answered (R2.1); one already admitted gains
//!   the binding as a source.
//! - **Withdrawals.** A source whose binding is gone, or whose group the member
//!   is no longer in, is dropped. An admission left with no source is owed a
//!   removal ([`DepartureCause::LeftGroup`]), which the departures worker drives
//!   exactly as it drives a departure from the community — remote first, with
//!   its own backoff. A binding being removed is deleted once nothing it covered
//!   still names it.
//! - **Renewals.** An admitted member a binding covers is renewed within a third
//!   of `validFor` of their authority's expiry: fresh membership and authority
//!   with the same actions, valid `validFor` from now, which the member collects
//!   from `vtc/rooms/offers/list/0.3` (bindings/add item 6).
//!
//! A VTA that does not answer is retried on a capped, jittered backoff kept in
//! memory: a restart retries at once, which a reconciler whose every step is
//! idempotent may do.

use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::rooms::community::{DepartureCause, MemberRecord, OwnedRoom, Renewal};
use crate::server::AppState;

/// The most bindings one group has (`tooManyBindings`).
pub const MAX_BINDINGS: usize = 64;
const TICK: Duration = Duration::from_secs(60);
const FIRST_PASS: Duration = Duration::from_secs(45);
const RETRY_BASE: Duration = Duration::from_secs(60);
const RETRY_CAP: Duration = Duration::from_secs(6 * 60 * 60);

/// A binding as this community stores it (`GroupBinding`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    pub binding_id: String,
    pub group_id: String,
    /// The `BindingSpec` as received, checked against its schema.
    pub binding: Value,
    /// `active` or `removing` (`pending` is never written: no binding this
    /// community serves is held for consent).
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: String,
}

impl Binding {
    pub const ACTIVE: &'static str = "active";
    pub const REMOVING: &'static str = "removing";

    /// The `GroupBinding` of `vtc/groups/_shared/0.1/group`.
    pub fn wire(&self) -> Value {
        json!({
            "bindingId": self.binding_id,
            "binding": self.binding,
            "state": self.state,
            "createdAt": self.created_at,
            "createdBy": self.created_by,
        })
    }

    /// The room binding this is, if it is one.
    pub fn room(&self) -> Option<RoomBinding> {
        RoomBinding::from_spec(&self.binding)
    }
}

/// A room binding's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomBinding {
    pub room_id: String,
    pub actions: Vec<String>,
    pub valid_for: chrono::Duration,
}

impl RoomBinding {
    pub fn from_spec(spec: &Value) -> Option<Self> {
        if spec.get("kind").and_then(Value::as_str) != Some("room") {
            return None;
        }
        let days: i64 = spec
            .get("validFor")
            .and_then(Value::as_str)?
            .strip_prefix('P')?
            .strip_suffix('D')?
            .parse()
            .ok()?;
        Some(Self {
            room_id: spec.get("roomId").and_then(Value::as_str)?.to_string(),
            actions: spec
                .get("actions")?
                .as_array()?
                .iter()
                .filter_map(|a| a.as_str().map(str::to_string))
                .collect(),
            valid_for: chrono::Duration::days(days),
        })
    }

    /// How long before an admission's expiry it is renewed: a third of its life.
    pub fn renew_within(&self) -> chrono::Duration {
        (self.valid_for / 3).max(chrono::Duration::hours(1))
    }
}

fn key(group_id: &str, binding_id: &str) -> Vec<u8> {
    format!("gbind:{group_id}:{binding_id}").into_bytes()
}

/// A fresh binding identifier: `gb_` and 22 characters of randomness.
pub fn new_binding_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "gb_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

pub async fn get(
    ks: &KeyspaceHandle,
    group_id: &str,
    binding_id: &str,
) -> Result<Option<Binding>, AppError> {
    ks.get(key(group_id, binding_id)).await
}

pub async fn put(ks: &KeyspaceHandle, b: &Binding) -> Result<(), AppError> {
    ks.insert(key(&b.group_id, &b.binding_id), b).await?;
    crate::admin_events::notify(crate::admin_events::Topic::Groups);
    kick();
    Ok(())
}

pub async fn delete(ks: &KeyspaceHandle, group_id: &str, binding_id: &str) -> Result<(), AppError> {
    ks.remove(key(group_id, binding_id)).await?;
    crate::admin_events::notify(crate::admin_events::Topic::Groups);
    Ok(())
}

async fn under(ks: &KeyspaceHandle, prefix: Vec<u8>) -> Result<Vec<Binding>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(prefix).await? {
        match serde_json::from_slice::<Binding>(&raw) {
            Ok(b) => out.push(b),
            Err(e) => tracing::warn!(error = %e, "skipping an unreadable group binding"),
        }
    }
    out.sort_by_key(|b| b.created_at);
    Ok(out)
}

/// A group's bindings, oldest first.
pub async fn of_group(ks: &KeyspaceHandle, group_id: &str) -> Result<Vec<Binding>, AppError> {
    under(ks, format!("gbind:{group_id}:").into_bytes()).await
}

/// Every binding.
pub async fn all(ks: &KeyspaceHandle) -> Result<Vec<Binding>, AppError> {
    under(ks, b"gbind:".to_vec()).await
}

/// Put every binding of a deleted group into removal: what they provided is
/// withdrawn by the reconciler, and each is deleted once nothing names it.
pub async fn on_group_deleted(ks: &KeyspaceHandle, group_id: &str) -> Result<usize, AppError> {
    let mut n = 0;
    for mut b in of_group(ks, group_id).await? {
        if b.state != Binding::REMOVING {
            b.state = Binding::REMOVING.into();
            put(ks, &b).await?;
            n += 1;
        }
    }
    Ok(n)
}

// ─── the reconciler ───────────────────────────────────────────────────────

static WAKE: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);

/// Wake the reconciler: a group's membership or bindings changed.
pub fn kick() {
    WAKE.notify_one();
}

/// Run the reconciler until shutdown. Always spawned: it does nothing while no
/// binding exists or there is no VTA link.
pub fn spawn(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut wait = FIRST_PASS;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(wait) => {}
                _ = WAKE.notified() => {}
            }
            wait = TICK;
            if let Err(e) = reconcile(&state, Utc::now()).await {
                tracing::warn!(error = %e, "group binding reconciliation failed");
            }
        }
    });
}

/// The retry schedule of each step that asks the VTA, by step.
static RETRIES: LazyLock<Mutex<HashMap<String, (u32, DateTime<Utc>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn due(step: &str, now: DateTime<Utc>) -> bool {
    RETRIES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(step)
        .is_none_or(|(_, next)| *next <= now)
}

fn failed(step: &str, now: DateTime<Utc>) -> u32 {
    use rand::RngExt as _;
    let mut map = RETRIES.lock().unwrap_or_else(|p| p.into_inner());
    let attempts = map.get(step).map_or(0, |(a, _)| *a) + 1;
    let factor = 1u32
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    let ceiling = RETRY_BASE.saturating_mul(factor).min(RETRY_CAP).as_secs();
    let half = ceiling / 2;
    let secs = half + rand::rng().random_range(0..=ceiling - half);
    map.insert(
        step.to_string(),
        (attempts, now + chrono::Duration::seconds(secs as i64)),
    );
    attempts
}

fn succeeded(step: &str) {
    RETRIES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(step);
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse(t: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(t)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// What a pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// `(room, member)` offered admission.
    pub offered: Vec<(String, String)>,
    /// `(room, member)` whose admission gained a binding as its source.
    pub covered: Vec<(String, String)>,
    /// `(room, member)` owed a removal: nothing covers them any longer.
    pub withdrawn: Vec<(String, String)>,
    /// `(room, member)` renewed.
    pub renewed: Vec<(String, String)>,
    /// Bindings deleted once nothing named them.
    pub deleted: Vec<String>,
    /// Steps that asked the VTA and failed.
    pub failed: usize,
}

/// The DIDs of `group_id`'s active members who are active members of the
/// community.
async fn members_of(state: &AppState, group_id: &str) -> Result<BTreeSet<String>, AppError> {
    let ks = state.directory.ks();
    let mut out = BTreeSet::new();
    for m in super::members_of(ks, group_id).await? {
        if m.state != "active" {
            continue;
        }
        let Some(card) = crate::directory::cards::get(ks, &m.entry_id).await? else {
            continue;
        };
        if crate::member_portal::active::active_member(state, &card.did)
            .await?
            .is_some()
        {
            out.insert(card.did);
        }
    }
    Ok(out)
}

/// One pass at `now`.
pub async fn reconcile(state: &AppState, now: DateTime<Utc>) -> Result<Report, AppError> {
    let mut report = Report::default();
    let ks = state.directory.ks();
    let bindings: Vec<Binding> = all(ks)
        .await?
        .into_iter()
        .filter(|b| b.room().is_some())
        .collect();
    if bindings.is_empty() {
        return Ok(report);
    }
    let Some(holder) = state.community_rooms.key_holder() else {
        return Ok(report);
    };
    let actor = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();

    // Who each live binding covers.
    let mut covered: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut groups_seen: HashMap<String, BTreeSet<String>> = HashMap::new();
    for b in &bindings {
        if b.state != Binding::ACTIVE || super::get(ks, &b.group_id).await?.is_none() {
            continue;
        }
        let members = match groups_seen.get(&b.group_id) {
            Some(m) => m.clone(),
            None => {
                let m = members_of(state, &b.group_id).await?;
                groups_seen.insert(b.group_id.clone(), m.clone());
                m
            }
        };
        covered.insert(b.binding_id.clone(), members);
    }
    let by_id: HashMap<&str, &Binding> = bindings
        .iter()
        .map(|b| (b.binding_id.as_str(), b))
        .collect();

    // Offers, and sources gained.
    for b in &bindings {
        let Some(members) = covered.get(&b.binding_id) else {
            continue;
        };
        let rb = b.room().expect("filtered to room bindings");
        let Some(room) = state.community_rooms.room(&rb.room_id).await? else {
            continue;
        };
        for did in members {
            offer_or_cover(state, &holder, &actor, b, &rb, &room, did, now, &mut report).await?;
        }
    }

    // Sources lost, removals owed, and renewals — over every room a binding names.
    let rooms: BTreeSet<String> = bindings
        .iter()
        .filter_map(|b| b.room().map(|r| r.room_id))
        .collect();
    for room_id in &rooms {
        let Some(room) = state.community_rooms.room(room_id).await? else {
            continue;
        };
        for record in state.community_rooms.members(room_id).await? {
            if record.state == MemberRecord::REMOVED {
                continue;
            }
            settle_sources(state, &room, record, &covered, &by_id, now, &mut report).await?;
        }
    }

    // A binding being removed goes once nothing names it.
    for b in bindings.iter().filter(|b| b.state == Binding::REMOVING) {
        let rb = b.room().expect("filtered to room bindings");
        let named = state
            .community_rooms
            .members(&rb.room_id)
            .await?
            .iter()
            .any(|r| r.state != MemberRecord::REMOVED && r.sources.contains(&b.binding_id));
        if !named {
            delete(ks, &b.group_id, &b.binding_id).await?;
            report.deleted.push(b.binding_id.clone());
        }
    }
    Ok(report)
}

/// Offer `did` admission to `room` through `b`, or add `b` to the sources of the
/// admission they already hold.
#[allow(clippy::too_many_arguments)]
async fn offer_or_cover(
    state: &AppState,
    holder: &crate::rooms::community::KeyHolder,
    actor: &str,
    b: &Binding,
    rb: &RoomBinding,
    room: &OwnedRoom,
    did: &str,
    now: DateTime<Utc>,
    report: &mut Report,
) -> Result<(), AppError> {
    let rooms = &state.community_rooms;
    let _guard = rooms.lock().await;
    let existing = rooms.member(&rb.room_id, did).await?;
    if let Some(mut r) = existing.filter(|r| r.state != MemberRecord::REMOVED) {
        if r.sources.contains(&b.binding_id) {
            return Ok(());
        }
        if r.sources.is_empty() {
            r.sources.push(MemberRecord::DIRECT.into());
        }
        r.sources.push(b.binding_id.clone());
        rooms.put_member(&r).await?;
        report.covered.push((rb.room_id.clone(), did.to_string()));
        return Ok(());
    }
    // A removal still owed (they left the group, then came back) is driven first;
    // the next pass offers again.
    if rooms.pending_removal(&rb.room_id, did).await?.is_some() {
        return Ok(());
    }
    let step = format!("offer:{}:{did}", rb.room_id);
    if !due(&step, now) {
        return Ok(());
    }
    let valid_until = rfc3339(now + rb.valid_for);
    let credentials = match crate::trust_tasks::community_room_tasks::issue_offer(
        holder,
        room,
        did,
        &rb.actions,
        &valid_until,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let attempts = failed(&step, now);
            tracing::warn!(room = %rb.room_id, attempts, error = ?e,
                "a group room binding's offer could not be issued; retrying later");
            report.failed += 1;
            return Ok(());
        }
    };
    succeeded(&step);
    let record = MemberRecord {
        room_id: rb.room_id.clone(),
        member: did.to_string(),
        actions: rb.actions.clone(),
        valid_until,
        state: MemberRecord::OFFERED.into(),
        offered_at: rfc3339(now),
        admitted_at: None,
        removed_at: None,
        credentials: Some(credentials),
        welcome: None,
        admitted_epoch: None,
        renewal: None,
        sources: vec![b.binding_id.clone()],
    };
    rooms.put_member(&record).await?;
    drop(_guard);
    let mut row = crate::trust_tasks::community_room_tasks::change("memberOffered", room);
    row.member = Some(did.to_string());
    row.actions = rb.actions.clone();
    row.reason = Some(format!("Group room binding {}.", b.binding_id));
    crate::trust_tasks::community_room_tasks::audit(state, actor, row).await;
    report.offered.push((rb.room_id.clone(), did.to_string()));
    Ok(())
}

/// Drop the sources of `record` that no longer cover it; owe its removal when
/// none is left; renew it when a binding covers it and it is due.
async fn settle_sources(
    state: &AppState,
    room: &OwnedRoom,
    record: MemberRecord,
    covered: &HashMap<String, BTreeSet<String>>,
    by_id: &HashMap<&str, &Binding>,
    now: DateTime<Utc>,
    report: &mut Report,
) -> Result<(), AppError> {
    if record.sources.is_empty() {
        return Ok(());
    }
    let rooms = &state.community_rooms;
    let keep: Vec<String> = record
        .sources
        .iter()
        .filter(|s| {
            s.as_str() == MemberRecord::DIRECT
                || covered
                    .get(s.as_str())
                    .is_some_and(|m| m.contains(&record.member))
        })
        .cloned()
        .collect();
    if keep != record.sources {
        let _guard = rooms.lock().await;
        let Some(mut current) = rooms.member(&record.room_id, &record.member).await? else {
            return Ok(());
        };
        if current.state == MemberRecord::REMOVED {
            return Ok(());
        }
        current
            .sources
            .retain(|s| keep.contains(s) || !record.sources.contains(s));
        if current.sources.iter().all(|s| s == MemberRecord::DIRECT) {
            // An administrator's direct admission, as it was before any binding.
            let direct = !current.sources.is_empty();
            current.sources.clear();
            rooms.put_member(&current).await?;
            if !direct {
                rooms
                    .record_removal(
                        &record.room_id,
                        &record.member,
                        DepartureCause::LeftGroup,
                        now,
                    )
                    .await?;
                report
                    .withdrawn
                    .push((record.room_id.clone(), record.member.clone()));
            }
        } else {
            rooms.put_member(&current).await?;
        }
        return Ok(());
    }
    // Renew an admitted member a binding covers.
    if record.state != MemberRecord::ADMITTED {
        return Ok(());
    }
    let Some(rb) = record
        .sources
        .iter()
        .filter_map(|s| by_id.get(s.as_str()).and_then(|b| b.room()))
        .max_by_key(|rb| rb.valid_for)
    else {
        return Ok(());
    };
    let Some(until) = parse(&record.valid_until) else {
        return Ok(());
    };
    if until - now > rb.renew_within() {
        return Ok(());
    }
    let step = format!("renew:{}:{}", record.room_id, record.member);
    if !due(&step, now) {
        return Ok(());
    }
    let Some(holder) = rooms.key_holder() else {
        return Ok(());
    };
    let valid_until = rfc3339(now + rb.valid_for);
    let issued = crate::trust_tasks::community_room_tasks::issue_renewal(
        &holder,
        room,
        &record.member,
        &record.actions,
        &valid_until,
    )
    .await;
    let (membership, authority) = match issued {
        Ok(c) => c,
        Err(e) => {
            let attempts = failed(&step, now);
            tracing::warn!(room = %record.room_id, attempts, error = ?e,
                "a bound room admission could not be renewed; retrying later");
            report.failed += 1;
            return Ok(());
        }
    };
    succeeded(&step);
    let _guard = rooms.lock().await;
    let Some(mut current) = rooms.member(&record.room_id, &record.member).await? else {
        return Ok(());
    };
    // Removed, or renewed by someone else, while the VTA was asked: that stands.
    if current.state != MemberRecord::ADMITTED || current.valid_until != record.valid_until {
        return Ok(());
    }
    current.renewal = Some(Renewal {
        membership,
        authority,
        valid_until: valid_until.clone(),
        renews: current.valid_until.clone(),
        issued_at: rfc3339(now),
    });
    // offers/list 0.3 item 7: the renewed expiry is the admission's own.
    current.valid_until = valid_until;
    rooms.put_member(&current).await?;
    report
        .renewed
        .push((record.room_id.clone(), record.member.clone()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_room_binding_reads_its_terms() {
        let rb = RoomBinding::from_spec(&json!({
            "kind": "room",
            "roomId": "did:webvh:Qm:rooms.example:wg",
            "actions": ["read", "write"],
            "validFor": "P30D",
        }))
        .unwrap();
        assert_eq!(rb.valid_for, chrono::Duration::days(30));
        assert_eq!(rb.renew_within(), chrono::Duration::days(10));
        assert!(RoomBinding::from_spec(&json!({ "kind": "grants", "grants": [] })).is_none());
    }

    #[test]
    fn binding_ids_match_their_pattern() {
        let id = new_binding_id();
        assert!(id.starts_with("gb_") && id.len() == 25, "{id}");
    }
}
