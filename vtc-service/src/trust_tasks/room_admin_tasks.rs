//! What this community's rooms store and may store — `vtc/rooms/get/0.1`,
//! `vtc/rooms/usage/0.1` and `vtc/rooms/limits/set/0.1`
//! (`docs/05-design-notes/data-rooms-files.md` §6.2–6.3, §8.1).
//!
//! The authority is `vtc.rooms.admin`, read from the signer's own entry at execution
//! time — the host's authority over rooms, never a room's. No room-issued credential is
//! required or accepted, and nothing here needs or could use a room key.
//!
//! Every answer is sizes and counts. None names a file, a record or a record key, because
//! the host cannot: those are sealed inside records it cannot open. Member DIDs appear
//! only in `vtc/rooms/usage`'s `member` rows, on rooms that are not `private` — the
//! disclosure that tier makes to its host anyway, stated where it is shown.
//!
//! A limit override is **not** parked for a second administrator (`vtc/rooms/limits/set`,
//! *Authorization*): an allowance is reversible, nothing is lost by it, and the room's
//! owner can see their own limits. It is audited with its reason.

use std::collections::BTreeMap;

use chrono::{Days, NaiveDate, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::vtc::rooms::get::v0_1 as get;
use trust_tasks_rs::specs::vtc::rooms::limits::set::v0_1 as set;
use trust_tasks_rs::specs::vtc::rooms::usage::v0_1 as usage;
use trust_tasks_rs::{Payload, TrustTask};
use vti_common::audit::{AuditEvent, RoomLimitsChangedData};
use vti_common::error::AppError;
use vti_rooms::blobs::{
    Activity, EffectiveLimits, LimitSource, LimitTarget, OverrideError, ScopeLimits, Usage,
};
use vti_rooms::{Room, Visibility};

use super::helpers::{TrustTaskOutcome, app_error_to_reject};
use super::storage_tasks::{malformed, refuse, respond, rooms_admin};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::server::AppState;

pub(crate) const GET_TYPE: &str = <get::Payload as Payload>::TYPE_URI;
pub(crate) const USAGE_TYPE: &str = <usage::Payload as Payload>::TYPE_URI;
pub(crate) const LIMITS_SET_TYPE: &str = <set::Payload as Payload>::TYPE_URI;

/// Every URI this module routes.
pub(crate) const URIS: &[&str] = &[GET_TYPE, USAGE_TYPE, LIMITS_SET_TYPE];

/// `largestBlobs` holds at most this many (`vtc/rooms/get`).
const LARGEST_BLOBS: usize = 10;
/// A usage page when the caller names no `limit`, and the most one holds.
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 100;
/// The default report range, in days, ending today (`vtc/rooms/usage` item 2).
const DEFAULT_RANGE_DAYS: u64 = 30;
/// The longest range a report may span.
const MAX_RANGE_DAYS: u64 = 400;
/// A usage cursor: this prefix, a digest of the query it pages, and an offset.
const CURSOR_PREFIX: &str = "vtc-rooms-usage:";

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        GET_TYPE => handle_get(state, ctx, doc).await,
        USAGE_TYPE => handle_usage(state, ctx, doc).await,
        LIMITS_SET_TYPE => handle_limits_set(state, ctx, doc).await,
        _ => return None,
    })
}

fn source_str(s: LimitSource) -> &'static str {
    match s {
        LimitSource::Default => "default",
        LimitSource::Override => "override",
    }
}

/// `EffectiveLimits` as `vtc/_shared/0.1/room-storage` states it.
fn effective_json(e: &EffectiveLimits) -> Value {
    json!({
        "limits": {
            "filesEnabled": e.files_enabled,
            "room": e.room,
            "member": e.member,
        },
        "roomSource": source_str(e.room_source),
        "memberSource": source_str(e.member_source),
        "hostCeilingBytes": e.host_ceiling_bytes,
    })
}

fn rfc3339(secs: u64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|t| t.to_rfc3339())
}

/// The room, or the task's `notFound` for one this community does not host.
async fn hosted(
    state: &AppState,
    doc: &TrustTask<Value>,
    room_id: &str,
    not_found: &str,
) -> Result<Room, TrustTaskOutcome> {
    match vti_rooms::storage::get_room(&state.rooms_ks, room_id).await {
        Ok(r) => Ok(r),
        Err(AppError::NotFound(_)) => Err(refuse(
            doc,
            not_found,
            format!("this community hosts no room `{room_id}`"),
            None,
        )),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// The config a room's new uploads go to: its assignment, else the default.
pub(super) async fn assigned_config(state: &AppState, room_id: &str) -> Result<String, AppError> {
    Ok(match state.room_storage.assignment(room_id).await? {
        Some(a) => a.config_id,
        None => state.room_storage.default_id().await?.unwrap_or_default(),
    })
}

// ─── vtc/rooms/get ───────────────────────────────────────────────────────

async fn handle_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let checked: get::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match get_body(state, &doc, checked.room_id.as_str()).await {
        Ok(body) => respond::<get::Response>(&doc, body),
        Err(reject) => reject,
    }
}

async fn get_body(
    state: &AppState,
    doc: &TrustTask<Value>,
    room_id: &str,
) -> Result<Value, TrustTaskOutcome> {
    let fail = |e: AppError| app_error_to_reject(doc, &e);
    let room = hosted(state, doc, room_id, get::error_codes::NOT_FOUND.code).await?;
    let files = &state.room_files;
    let config_id = assigned_config(state, room_id).await.map_err(fail)?;
    let summary = files
        .room_blobs_summary(room_id, LARGEST_BLOBS)
        .await
        .map_err(fail)?;
    let limits = files.effective_limits(&room).await.map_err(fail)?;
    let room_usage = files.room_usage(room_id).await.map_err(fail)?;
    let host_record = crate::routes::rooms::hosted_room(state, room_id)
        .await
        .map_err(fail)?;

    // Item 4: every other config still holding a blob of this room.
    let earlier: Vec<Value> = summary
        .by_config
        .iter()
        .filter(|(id, h)| **id != config_id && h.files > 0)
        .map(|(id, h)| json!({ "configId": id, "files": h.files, "bytes": h.bytes }))
        .collect();
    let largest: Vec<Value> = summary
        .largest
        .iter()
        .filter(|(size, ..)| *size > 0)
        .map(|(size, config, at)| {
            json!({ "size": size, "configId": config, "createdAt": rfc3339(*at) })
        })
        .collect();
    let mut orphans = json!({ "files": summary.orphan_files, "bytes": summary.orphan_bytes });
    if let Some(at) = summary.oldest_orphaned_at.and_then(rfc3339) {
        orphans["oldestOrphanedAt"] = json!(at);
    }

    let mut storage = json!({ "configId": config_id, "earlierConfigs": earlier });
    // The room's migration, as `vtc/rooms/storage/migrate` reports it: the last one, in
    // whatever state, so a console sees one finish or fail as well as run.
    if let Some(m) = files.migration(room_id).await.map_err(fail)? {
        storage["migration"] = crate::rooms::migration::progress_json(&m);
    }
    let mut body = json!({
        "room": host_record,
        "storage": storage,
        "limits": effective_json(&limits),
        "usage": { "room": room_usage, "orphans": orphans },
        "largestBlobs": largest,
    });
    // Item 5: a count, never the DIDs, and none on a private room.
    if room.visibility != Visibility::Private {
        let n = files.members_with_usage(&room).await.map_err(fail)?.len();
        body["membersWithUsage"] = json!(n);
    }
    Ok(body)
}

// ─── vtc/rooms/limits/set ────────────────────────────────────────────────

async fn handle_limits_set(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use set::error_codes as c;
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: set::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room_id = checked.room_id.as_str().to_string();

    // Item 2: a member target names its member, and no other target does.
    let member = checked
        .target
        .member
        .as_ref()
        .map(|m| m.as_str().to_string());
    let target = match (checked.target.kind, member) {
        (set::LimitTargetKind::Room, None) => LimitTarget::Room,
        (set::LimitTargetKind::MemberDefault, None) => LimitTarget::MemberDefault,
        (set::LimitTargetKind::Member, Some(m)) => LimitTarget::Member(m),
        (set::LimitTargetKind::Member, None) => {
            return malformed(&doc, "a `member` target names its `member`");
        }
        (set::LimitTargetKind::Room | set::LimitTargetKind::MemberDefault, Some(_)) => {
            return malformed(&doc, "only a `member` target names a `member`");
        }
        (other, _) => {
            return malformed(
                &doc,
                format!("target kind {other:?} is not one this community knows"),
            );
        }
    };
    // The producer rule: exactly one change — `limits`, `clear: true`, or (room
    // target only) `filesEnabled`, alone or with `limits`.
    let clear = checked.clear.unwrap_or(false);
    let files_enabled = checked.files_enabled;
    let combination = if files_enabled.is_some() && target != LimitTarget::Room {
        Some("`filesEnabled` is set on the room, not on a member scope")
    } else if clear && (checked.limits.is_some() || files_enabled.is_some()) {
        Some("`clear` stands alone")
    } else if !clear && checked.limits.is_none() && files_enabled.is_none() {
        Some("name one change: `limits`, `clear: true` or `filesEnabled`")
    } else {
        None
    };
    if let Some(why) = combination {
        return refuse(&doc, c::INVALID_COMBINATION.code, why, None);
    }
    let limits: Option<ScopeLimits> = match &checked.limits {
        None => None,
        Some(l) => match serde_json::to_value(l).and_then(serde_json::from_value) {
            Ok(l) => Some(l),
            Err(e) => return malformed(&doc, format!("`limits`: {e}")),
        },
    };

    let room = match hosted(state, &doc, &room_id, c::NOT_FOUND.code).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let files = &state.room_files;
    let change = match files
        .set_limit_override(&room, &target, limits, files_enabled)
        .await
    {
        Ok(c) => c,
        Err(e @ OverrideError::AboveCeiling { requested, ceiling }) => {
            return refuse(
                &doc,
                c::ABOVE_CEILING.code,
                e.to_string(),
                Some(json!({ "requested": requested, "ceiling": ceiling })),
            );
        }
        Err(e @ OverrideError::MemberLimitsUnavailable) => {
            return refuse(&doc, c::MEMBER_LIMITS_UNAVAILABLE.code, e.to_string(), None);
        }
        Err(OverrideError::App(e)) => return app_error_to_reject(&doc, &e),
        // `OverrideError` is `#[non_exhaustive]`.
        Err(e) => {
            return app_error_to_reject(
                &doc,
                &vti_common::error::AppError::Internal(e.to_string()),
            );
        }
    };

    // Item 7, written before the answer: the change has been made.
    let target_json = match &target {
        LimitTarget::Room => json!({ "kind": "room" }),
        LimitTarget::MemberDefault => json!({ "kind": "memberDefault" }),
        LimitTarget::Member(m) => json!({ "kind": "member", "member": m }),
    };
    let current_override = files.limit_override(&room, &target).await.ok().flatten();
    let effective = match files.effective_limits(&room).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let snapshot = |limits: Option<ScopeLimits>, files_enabled: Option<bool>| {
        let mut v = serde_json::Map::new();
        if let Some(l) = limits {
            v.insert("limits".into(), json!(l));
        }
        if let Some(f) = files_enabled {
            v.insert("filesEnabled".into(), json!(f));
        }
        (!v.is_empty()).then_some(Value::Object(v))
    };
    let current_files_enabled = (target == LimitTarget::Room)
        .then_some(effective.files_enabled)
        .filter(|_| files_enabled.is_some() || change.previous_files_enabled.is_some());
    audit(
        state,
        &actor.did,
        RoomLimitsChangedData {
            room_id: room_id.clone(),
            target: target_json.clone(),
            previous: snapshot(change.previous, change.previous_files_enabled),
            current: snapshot(current_override, current_files_enabled),
            reason: checked.reason.as_str().to_string(),
        },
    )
    .await;

    // Item 8: the effective limits after, the target scope's usage, and whether it
    // already exceeds them.
    let (target_limits, scope_usage, over) = match &target {
        LimitTarget::Room => {
            let u = files.room_usage(&room_id).await.unwrap_or_default();
            (effective.room, u, exceeds(&u, &effective.room))
        }
        LimitTarget::MemberDefault => {
            // Every member held to the default, which is everyone without their own.
            let members = files.members_with_usage(&room).await.unwrap_or_default();
            let over = members
                .iter()
                .any(|m| !m.overridden && exceeds(&m.usage, &effective.member));
            let u = files.room_usage(&room_id).await.unwrap_or_default();
            (effective.member, u, over)
        }
        LimitTarget::Member(m) => {
            let u = files.member_usage(&room_id, m).await.unwrap_or_default();
            let l = match files.member_limits(&room, m).await {
                Ok(l) => l.limits,
                Err(e) => return app_error_to_reject(&doc, &e),
            };
            (l, u, exceeds(&u, &l))
        }
    };
    respond::<set::Response>(
        &doc,
        json!({
            "roomId": room_id,
            "target": target_json,
            "limits": effective_json(&effective),
            "targetLimits": target_limits,
            "usage": scope_usage,
            "overLimit": over,
        }),
    )
}

/// Whether `u` already holds more than `l` allows. Reservations count: they are
/// uploads the limit will have to hold.
fn exceeds(u: &Usage, l: &ScopeLimits) -> bool {
    l.max_files.is_some_and(|m| u.files + u.reserved_files > m)
        || l.max_bytes.is_some_and(|m| u.bytes + u.reserved_bytes > m)
}

async fn audit(state: &AppState, actor: &str, data: RoomLimitsChangedData) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    if let Err(e) = writer
        .write(actor, None, AuditEvent::RoomLimitsChanged(data))
        .await
    {
        tracing::warn!(error = %e, "could not audit a room limit change");
    }
}

// ─── vtc/rooms/usage ─────────────────────────────────────────────────────

/// One row before it is rendered: its group key, holdings and activity.
#[derive(Default)]
struct Row {
    room_id: Option<String>,
    member: Option<String>,
    storage_config: Option<String>,
    date: Option<NaiveDate>,
    files: u64,
    bytes: u64,
    reserved_bytes: u64,
    activity: Activity,
    limits: Option<ScopeLimits>,
    capacity_bytes: Option<u64>,
}

impl Row {
    fn add_holdings(&mut self, u: &Usage) {
        self.files += u.files;
        self.bytes += u.bytes;
        self.reserved_bytes += u.reserved_bytes;
    }
    fn add_activity(&mut self, a: Activity) {
        self.activity.uploads += a.uploads;
        self.activity.downloads += a.downloads;
        self.activity.egress_bytes += a.egress_bytes;
    }
    fn render(&self) -> Value {
        let mut v = json!({
            "files": self.files,
            "bytes": self.bytes,
            "reservedBytes": self.reserved_bytes,
            "uploads": self.activity.uploads,
            "downloads": self.activity.downloads,
            "egressBytes": self.activity.egress_bytes,
        });
        if let Some(r) = &self.room_id {
            v["roomId"] = json!(r);
        }
        if let Some(m) = &self.member {
            v["member"] = json!(m);
        }
        if let Some(c) = &self.storage_config {
            v["storageConfig"] = json!(c);
        }
        if let Some(d) = self.date {
            v["date"] = json!(d);
        }
        if let Some(l) = &self.limits {
            v["limits"] = json!(l);
        }
        if let Some(c) = self.capacity_bytes {
            v["capacityBytes"] = json!(c);
        }
        v
    }
}

async fn handle_usage(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use usage::error_codes as c;
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let checked: usage::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let fail = |e: AppError| app_error_to_reject(&doc, &e);
    let files = &state.room_files;
    let filter = checked.filter.clone().unwrap_or_default();

    // Item 2: the range, inclusive, defaulting to the last 30 days. An explicit
    // start before the oldest retained day is refused; the default is clipped to
    // it, so a community with a short history still gets its default report.
    let today = Utc::now().date_naive();
    let oldest = match files.oldest_retained_day().await {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let to = filter.to.unwrap_or(today);
    let from = match filter.from {
        Some(f) => f,
        None => {
            let default = to - Days::new(DEFAULT_RANGE_DAYS - 1);
            oldest.map_or(default, |o| default.max(o).min(to))
        }
    };
    let span = (to - from).num_days() + 1;
    let invalid = if from > to {
        Some("`from` is after `to`".to_string())
    } else if span as u64 > MAX_RANGE_DAYS {
        Some(format!(
            "{span} days is more than the {MAX_RANGE_DAYS} a report may span"
        ))
    } else if filter.from.is_some() && oldest.is_some_and(|o| from < o) {
        Some("the range starts before the oldest day this community has kept".to_string())
    } else {
        None
    };
    if let Some(why) = invalid {
        let details = oldest.map(|o| json!({ "earliest": o }));
        return refuse(&doc, c::INVALID_RANGE.code, why, details);
    }

    // The rooms the report covers: those that have held files, narrowed by the filter.
    let mut rooms: Vec<Room> = Vec::new();
    let room_ids = match &filter.room_id {
        Some(r) => vec![r.as_str().to_string()],
        None => match files.rooms_with_files().await {
            Ok(r) => r,
            Err(e) => return fail(e),
        },
    };
    let mut config_of = BTreeMap::new();
    for id in room_ids {
        let room = match vti_rooms::storage::get_room(&state.rooms_ks, &id).await {
            Ok(r) => r,
            // A room no longer hosted has nothing to report against.
            Err(AppError::NotFound(_)) => continue,
            Err(e) => return fail(e),
        };
        let config = match assigned_config(state, &id).await {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
        if filter
            .storage_config
            .as_ref()
            .is_some_and(|c| c.as_str() != config)
        {
            continue;
        }
        config_of.insert(id, config);
        rooms.push(room);
    }

    // Item 4: member figures exist only where the host can tell members apart.
    let by_member = matches!(checked.group_by, usage::PayloadGroupBy::Member);
    let member_filter = filter.member.as_ref().map(|m| m.as_str().to_string());
    if (by_member || member_filter.is_some())
        && filter.room_id.is_some()
        && rooms.iter().any(|r| r.visibility == Visibility::Private)
    {
        return refuse(
            &doc,
            c::MEMBER_USAGE_UNAVAILABLE.code,
            "a private room's uploads are not attributed to members, by design",
            None,
        );
    }
    if by_member || member_filter.is_some() {
        rooms.retain(|r| r.visibility != Visibility::Private);
    }

    // A config grouping covers every config, or those the filter names: the one
    // given, or those the named room is on.
    let only_configs: Option<std::collections::HashSet<String>> =
        match (&filter.storage_config, &filter.room_id) {
            (Some(c), _) => Some([c.as_str().to_string()].into()),
            (None, Some(_)) => Some(config_of.values().cloned().collect()),
            (None, None) => None,
        };
    let rows = match build_rows(
        state,
        checked.group_by,
        &rooms,
        &config_of,
        member_filter.as_deref(),
        only_configs.as_ref(),
        from,
        to,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let mut rows = rows;
    sort_rows(&mut rows, checked.group_by, checked.sort.as_ref());

    // Item 5: pages, and a cursor bound to the query it pages.
    let query = query_digest(&checked);
    let offset = match checked.cursor.as_ref() {
        None => 0,
        Some(cursor) => match parse_cursor(cursor.as_str(), &query) {
            Some(o) => o,
            None => {
                return refuse(
                    &doc,
                    c::INVALID_CURSOR.code,
                    "`cursor` is not one this community issued for this query",
                    None,
                );
            }
        },
    };
    let limit = checked
        .limit
        .map_or(DEFAULT_PAGE, |l| (l.get() as usize).min(MAX_PAGE));
    let page: Vec<Value> = rows
        .iter()
        .skip(offset)
        .take(limit)
        .map(Row::render)
        .collect();
    let mut body = json!({
        "asOf": Utc::now().to_rfc3339(),
        "from": from,
        "to": to,
        "items": page,
    });
    if offset + limit < rows.len() {
        body["nextCursor"] = json!(format!("{CURSOR_PREFIX}{query}:{}", offset + limit));
    }
    respond::<usage::Response>(&doc, body)
}

async fn build_rows(
    state: &AppState,
    group_by: usage::PayloadGroupBy,
    rooms: &[Room],
    config_of: &BTreeMap<String, String>,
    member: Option<&str>,
    only_configs: Option<&std::collections::HashSet<String>>,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<Row>, AppError> {
    let files = &state.room_files;
    let mut out = Vec::new();
    match group_by {
        usage::PayloadGroupBy::Room => {
            for room in rooms {
                let id = &room.room_id;
                let mut row = Row {
                    room_id: Some(id.clone()),
                    storage_config: config_of.get(id).cloned(),
                    ..Row::default()
                };
                match member {
                    // One member's share of each room.
                    Some(m) => {
                        row.add_holdings(&files.member_usage(id, m).await?);
                        row.add_activity(files.member_activity(id, m, from, to).await?);
                        row.limits = Some(files.member_limits(room, m).await?.limits);
                    }
                    None => {
                        row.add_holdings(&files.room_usage(id).await?);
                        row.add_activity(files.room_activity(id, from, to).await?);
                        row.limits = Some(files.effective_limits(room).await?.room);
                    }
                }
                out.push(row);
            }
        }
        usage::PayloadGroupBy::Member => {
            let mut by: BTreeMap<String, Row> = BTreeMap::new();
            for room in rooms {
                for m in files.members_with_usage(room).await? {
                    if member.is_some_and(|f| f != m.member) {
                        continue;
                    }
                    let a = files
                        .member_activity(&room.room_id, &m.member, from, to)
                        .await?;
                    let row = by.entry(m.member.clone()).or_insert_with(|| Row {
                        member: Some(m.member.clone()),
                        ..Row::default()
                    });
                    row.add_holdings(&m.usage);
                    row.add_activity(a);
                    // Limits belong to one room; across several there is no one answer.
                    row.limits = (rooms.len() == 1).then_some(m.limits);
                }
            }
            out.extend(by.into_values());
        }
        usage::PayloadGroupBy::StorageConfig => {
            let holdings = files.config_holdings().await?;
            let mut by: BTreeMap<String, Row> = BTreeMap::new();
            for record in state.room_storage.configs().await? {
                let id = record["id"].as_str().unwrap_or_default().to_string();
                let h = holdings.get(&id).copied().unwrap_or_default();
                by.insert(
                    id.clone(),
                    Row {
                        storage_config: Some(id),
                        files: h.files,
                        bytes: h.bytes,
                        capacity_bytes: record["capacityBytes"].as_u64(),
                        ..Row::default()
                    },
                );
            }
            // Activity is counted per room, and attributed here to the config each
            // room is assigned to now.
            for room in rooms {
                if let Some(row) = config_of.get(&room.room_id).and_then(|c| by.get_mut(c)) {
                    row.add_activity(files.room_activity(&room.room_id, from, to).await?);
                }
            }
            out.extend(by.into_values().filter(|r| {
                only_configs
                    .is_none_or(|only| r.storage_config.as_ref().is_some_and(|c| only.contains(c)))
            }));
        }
        usage::PayloadGroupBy::Day => {
            let mut by: BTreeMap<NaiveDate, Row> = BTreeMap::new();
            for room in rooms {
                let days = match member {
                    Some(m) => files.member_days(&room.room_id, m, from, to).await?,
                    None => files.room_days(&room.room_id, from, to).await?,
                };
                for d in days {
                    let row = by.entry(d.date).or_insert_with(|| Row {
                        date: Some(d.date),
                        ..Row::default()
                    });
                    row.files += d.files;
                    row.bytes += d.bytes;
                    row.add_activity(d.activity());
                }
            }
            out.extend(by.into_values());
        }
        other => {
            return Err(AppError::Validation(format!(
                "groupBy {other:?} is not one this community reports"
            )));
        }
    }
    Ok(out)
}

fn sort_rows(rows: &mut [Row], group_by: usage::PayloadGroupBy, sort: Option<&usage::PayloadSort>) {
    use usage::{PayloadSortBy as By, PayloadSortOrder as Order};
    let default_by = if matches!(group_by, usage::PayloadGroupBy::Day) {
        By::Date
    } else {
        By::Bytes
    };
    let by = sort.map_or(default_by, |s| s.by);
    let ascending = match sort.and_then(|s| s.order) {
        Some(Order::Asc) => true,
        Some(Order::Desc) => false,
        Some(_) | None => matches!(by, By::Date),
    };
    let key = |r: &Row| -> u64 {
        match by {
            By::Bytes => r.bytes,
            By::Files => r.files,
            By::Uploads => r.activity.uploads,
            By::Downloads => r.activity.downloads,
            By::EgressBytes => r.activity.egress_bytes,
            By::Date => r.date.map_or(0, |d| {
                d.signed_duration_since(NaiveDate::MIN).num_days() as u64
            }),
            _ => r.bytes,
        }
    };
    // Stable, so rows that tie keep their group order (room, member, config, date).
    rows.sort_by(|a, b| {
        let (ka, kb) = (key(a), key(b));
        if ascending { ka.cmp(&kb) } else { kb.cmp(&ka) }
    });
}

/// What a cursor is bound to: everything but the cursor and the page size.
fn query_digest(p: &usage::Payload) -> String {
    let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.remove("cursor");
        o.remove("limit");
    }
    let canonical = serde_json::to_string(&v).unwrap_or_default();
    Sha256::digest(canonical.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn parse_cursor(cursor: &str, query: &str) -> Option<usize> {
    let rest = cursor.strip_prefix(CURSOR_PREFIX)?;
    let (q, offset) = rest.split_once(':')?;
    (q == query).then_some(())?;
    offset.parse().ok()
}
