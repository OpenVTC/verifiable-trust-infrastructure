//! Invitations, invitation links, opt-outs, announcements and partner communities
//! (VTI-EVT-100 – 135), and the `event` notification that carries an invitation
//! (VTI-NTF-064 – 067).
//!
//! # Remote first, one sender
//!
//! An invitation is a record of its own (`inv:<eventId>:<entryId>`), written **before** anything
//! is sent, with the notification it carries beside it: its `notificationId`, the revision the
//! invitee should hold, whether it is withdrawn, the revision last queued and the event
//! `sequence` the latest revision states. A partner community's notification is a record of the
//! same shape (`pnotice:<eventId>:<partnerDid>`). [`settle`], run by the events sweeper every
//! minute and kicked on every change that may move one, is the only sender (VTI-EVT-102):
//!
//! 1. under `notify` / `expect`, each member of a published event's audience who holds no
//!    registration, no invitation and no opt-out covering it is invited (VTI-EVT-101, 108, 110);
//! 2. each invitation and partner notice is raised a revision when the event's `sequence` moved,
//!    and withdrawn when the event is cancelled, the invitation revoked, or its invitee no longer
//!    in the audience (VTI-NTF-065);
//! 3. a revision not yet queued is queued on the durable member push. An offering revision goes
//!    only to a party the community's records still show as concerned; a withdrawal goes
//!    regardless (VTI-NTF-005).
//!
//! Nothing is sent once the event has ended: its notification has lapsed (VTI-NTF-064).
//! A notification carries only the reference — the community, the event's identifier, the task
//! that opens it, the audience and the event's period — never its title, place, hosts or anyone
//! else invited (VTI-NTF-003).

use std::collections::BTreeSet;

use base64::Engine as _;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use vta_sdk::notifications::{EVENT_OPEN_WITH, KIND_EVENT};
use vta_sdk::trust_tasks::TASK_NOTIFICATIONS_NOTIFY_0_1;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{EventRecord, Lifecycle, new_id_with};
use crate::server::AppState;

// ─── records ─────────────────────────────────────────────────────────────

/// `EventInviteMode` (VTI-EVT-100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum InviteMode {
    #[default]
    None,
    Notify,
    Expect,
}

impl InviteMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Notify => "notify",
            Self::Expect => "expect",
        }
    }
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "notify" => Some(Self::Notify),
            "expect" => Some(Self::Expect),
            _ => None,
        }
    }
}

/// `EventInviter` (VTI-EVT-106).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Inviter {
    Audience,
    Host,
    Member,
    Link,
}

impl Inviter {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audience => "audience",
            Self::Host => "host",
            Self::Member => "member",
            Self::Link => "link",
        }
    }
    /// A host's or a link's invitation puts its invitee in the audience while it stands
    /// (VTI-EVT-103, VTI-EVT-107); the community's and a member's never widen it (VTI-EVT-105).
    #[must_use]
    pub fn widens(self) -> bool {
        matches!(self, Self::Host | Self::Link)
    }
}

/// `EventInvitationAnswer` (VTI-EVT-104).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Answer {
    None,
    Going,
    Maybe,
    Declined,
}

impl Answer {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Going => "going",
            Self::Maybe => "maybe",
            Self::Declined => "declined",
        }
    }
}

/// One notification the community sends and keeps in step (VTI-NTF-065).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    /// Unguessable and not descriptive: it travels as far as the notification is relayed.
    pub notification_id: String,
    /// The revision the recipient should hold.
    pub revision: u64,
    pub withdrawn: bool,
    /// The highest revision queued for delivery; 0 for none.
    pub queued_revision: u64,
    /// The event `sequence` the latest revision states.
    pub sequence: u64,
}

impl Notice {
    fn new(sequence: u64) -> Self {
        Self {
            notification_id: format!("ntf-{}", uuid::Uuid::new_v4().simple()),
            revision: 1,
            withdrawn: false,
            queued_revision: 0,
            sequence,
        }
    }
}

/// One member's invitation to one event (VTI-EVT-102).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invitation {
    pub invitation_id: String,
    pub event_id: String,
    pub entry_id: String,
    /// The invitee's membership DID when invited: the notification's audience (VTI-NTF-064).
    pub did: String,
    pub invited_by: Inviter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inviter_entry_id: Option<String>,
    pub reply_expected: bool,
    pub answer: Answer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    pub notice: Notice,
}

impl Invitation {
    /// Whether it puts its invitee in the event's audience now (VTI-EVT-103).
    #[must_use]
    pub fn widens(&self) -> bool {
        !self.revoked && self.invited_by.widens()
    }
}

/// The notification sent to one partner community about one event (VTI-EVT-131).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartnerNotice {
    pub event_id: String,
    pub partner: String,
    pub notice: Notice,
}

/// An invitation link (VTI-EVT-107). The code is never stored: only its SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    pub link_id: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub max_redemptions: u32,
    pub redemptions: u32,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub digest: String,
}

/// A member's opt-out of invitations (VTI-EVT-110).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptOut {
    /// `event` or `calendar`.
    pub scope: String,
    /// The event's or the calendar's identifier.
    pub id: String,
    pub created_at: DateTime<Utc>,
}

/// A host's announcement to an event's registrants (VTI-EVT-120).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announcement {
    pub announcement_id: String,
    pub event_id: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posted_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ─── storage ─────────────────────────────────────────────────────────────

fn inv_key(event: &str, entry: &str) -> String {
    format!("inv:{event}:{entry}")
}
fn iid_key(id: &str) -> String {
    format!("iid:{id}")
}
fn minv_key(entry: &str, event: &str) -> String {
    format!("minv:{entry}:{event}")
}
fn pnotice_key(event: &str, partner: &str) -> String {
    format!("pnotice:{event}:{partner}")
}
fn lnk_key(id: &str) -> String {
    format!("lnk:{id}")
}
fn lnkd_key(digest: &str) -> String {
    format!("lnkd:{digest}")
}
fn lnkr_key(id: &str, entry: &str) -> String {
    format!("lnkr:{id}:{entry}")
}
fn opt_key(entry: &str, scope: &str, id: &str) -> String {
    format!("opt:{entry}:{scope}:{id}")
}
fn ann_key(event: &str, id: &str) -> String {
    format!("ann:{event}:{id}")
}

async fn values<T: serde::de::DeserializeOwned>(
    ks: &KeyspaceHandle,
    prefix: &str,
) -> Result<Vec<T>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(prefix.as_bytes().to_vec()).await? {
        match serde_json::from_slice(&raw) {
            Ok(v) => out.push(v),
            Err(e) => {
                tracing::warn!(prefix, error = %e, "an events record could not be read; skipped")
            }
        }
    }
    Ok(out)
}

/// # Errors
/// A store failure.
pub async fn get_invitation(
    ks: &KeyspaceHandle,
    event: &str,
    entry: &str,
) -> Result<Option<Invitation>, AppError> {
    ks.get(inv_key(event, entry)).await
}

/// # Errors
/// A store failure.
pub async fn invitation_by_id(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<Invitation>, AppError> {
    let Some(raw) = ks.get_raw(iid_key(id)).await? else {
        return Ok(None);
    };
    let at = String::from_utf8(raw).unwrap_or_default();
    let Some((event, entry)) = at.split_once(' ') else {
        return Ok(None);
    };
    get_invitation(ks, event, entry).await
}

/// # Errors
/// A store failure.
pub async fn put_invitation(ks: &KeyspaceHandle, inv: &Invitation) -> Result<(), AppError> {
    ks.insert_raw(
        iid_key(&inv.invitation_id),
        format!("{} {}", inv.event_id, inv.entry_id).into_bytes(),
    )
    .await?;
    ks.insert_raw(minv_key(&inv.entry_id, &inv.event_id), Vec::new())
        .await?;
    ks.insert(inv_key(&inv.event_id, &inv.entry_id), inv).await
}

/// Every invitation to `event`.
///
/// # Errors
/// A store failure.
pub async fn invitations_of(ks: &KeyspaceHandle, event: &str) -> Result<Vec<Invitation>, AppError> {
    values(ks, &format!("inv:{event}:")).await
}

/// Every invitation `entry` holds.
///
/// # Errors
/// A store failure.
pub async fn invitations_by(ks: &KeyspaceHandle, entry: &str) -> Result<Vec<Invitation>, AppError> {
    let prefix = format!("minv:{entry}:");
    let mut out = Vec::new();
    for key in ks.prefix_keys(prefix.as_bytes().to_vec()).await? {
        let Ok(key) = String::from_utf8(key) else {
            continue;
        };
        if let Some(event) = key.strip_prefix(&prefix)
            && let Some(i) = get_invitation(ks, event, entry).await?
        {
            out.push(i);
        }
    }
    Ok(out)
}

/// Record an invitation, unless the member holds one already (VTI-EVT-102: at most one). The
/// record is written before anything is sent; [`settle`] sends it. Returns the invitation and
/// whether it is new.
///
/// # Errors
/// A store failure.
pub async fn invite(
    ks: &KeyspaceHandle,
    ev: &EventRecord,
    entry: &str,
    did: &str,
    by: Inviter,
    inviter_entry: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(Invitation, bool), AppError> {
    if let Some(existing) = get_invitation(ks, &ev.event_id, entry).await? {
        return Ok((existing, false));
    }
    let inv = Invitation {
        invitation_id: new_id_with("inv"),
        event_id: ev.event_id.clone(),
        entry_id: entry.to_string(),
        did: did.to_string(),
        invited_by: by,
        inviter_entry_id: inviter_entry.map(str::to_string),
        reply_expected: ev.invite == InviteMode::Expect,
        answer: Answer::None,
        answered_at: None,
        revoked: false,
        created_at: now,
        notice: Notice::new(ev.sequence),
    };
    put_invitation(ks, &inv).await?;
    Ok((inv, true))
}

/// Record the invitee's answer, where they hold an invitation (VTI-EVT-104).
///
/// # Errors
/// A store failure.
pub async fn record_answer(
    ks: &KeyspaceHandle,
    event: &str,
    entry: &str,
    answer: Answer,
    now: DateTime<Utc>,
) -> Result<Option<Invitation>, AppError> {
    let Some(mut inv) = get_invitation(ks, event, entry).await? else {
        return Ok(None);
    };
    if inv.revoked {
        return Ok(Some(inv));
    }
    inv.answer = answer;
    inv.answered_at = Some(now);
    put_invitation(ks, &inv).await?;
    Ok(Some(inv))
}

/// How many invitations `entry` made as a member since `since` (VTI-EVT-105's daily limit).
///
/// # Errors
/// A store failure.
pub async fn member_invitations_since(
    ks: &KeyspaceHandle,
    entry: &str,
    since: DateTime<Utc>,
) -> Result<usize, AppError> {
    Ok(values::<Invitation>(ks, "inv:")
        .await?
        .iter()
        .filter(|i| {
            i.invited_by == Inviter::Member
                && i.inviter_entry_id.as_deref() == Some(entry)
                && i.created_at >= since
        })
        .count())
}

// ── links ──

/// A new code: 256 random bits, base64url (VTI-EVT-107).
#[must_use]
pub fn new_code() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The digest a code is kept as.
#[must_use]
pub fn code_digest(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// # Errors
/// A store failure.
pub async fn put_link(ks: &KeyspaceHandle, link: &Link) -> Result<(), AppError> {
    ks.insert_raw(lnkd_key(&link.digest), link.link_id.clone().into_bytes())
        .await?;
    ks.insert(lnk_key(&link.link_id), link).await
}

/// # Errors
/// A store failure.
pub async fn get_link(ks: &KeyspaceHandle, id: &str) -> Result<Option<Link>, AppError> {
    ks.get(lnk_key(id)).await
}

/// The link a code names, by its digest.
///
/// # Errors
/// A store failure.
pub async fn link_for_code(ks: &KeyspaceHandle, code: &str) -> Result<Option<Link>, AppError> {
    let Some(raw) = ks.get_raw(lnkd_key(&code_digest(code))).await? else {
        return Ok(None);
    };
    get_link(ks, &String::from_utf8(raw).unwrap_or_default()).await
}

/// # Errors
/// A store failure.
pub async fn links_of(ks: &KeyspaceHandle, event: &str) -> Result<Vec<Link>, AppError> {
    Ok(values::<Link>(ks, "lnk:")
        .await?
        .into_iter()
        .filter(|l| l.event_id == event)
        .collect())
}

/// Whether `entry` redeemed `link` already.
///
/// # Errors
/// A store failure.
pub async fn redeemed(ks: &KeyspaceHandle, link: &str, entry: &str) -> Result<bool, AppError> {
    Ok(ks.get_raw(lnkr_key(link, entry)).await?.is_some())
}

/// Record a redemption and count it.
///
/// # Errors
/// A store failure.
pub async fn record_redemption(
    ks: &KeyspaceHandle,
    link: &mut Link,
    entry: &str,
) -> Result<(), AppError> {
    ks.insert_raw(lnkr_key(&link.link_id, entry), Vec::new())
        .await?;
    link.redemptions += 1;
    put_link(ks, link).await
}

// ── opt-outs ──

/// # Errors
/// A store failure.
pub async fn set_opt_out(
    ks: &KeyspaceHandle,
    entry: &str,
    scope: &str,
    id: &str,
    out: bool,
    now: DateTime<Utc>,
) -> Result<Option<OptOut>, AppError> {
    let key = opt_key(entry, scope, id);
    if !out {
        ks.remove(key).await?;
        return Ok(None);
    }
    if let Some(existing) = ks.get::<OptOut>(key.clone()).await? {
        return Ok(Some(existing));
    }
    let o = OptOut {
        scope: scope.to_string(),
        id: id.to_string(),
        created_at: now,
    };
    ks.insert(key, &o).await?;
    Ok(Some(o))
}

/// # Errors
/// A store failure.
pub async fn opt_outs(ks: &KeyspaceHandle, entry: &str) -> Result<Vec<OptOut>, AppError> {
    values(ks, &format!("opt:{entry}:")).await
}

/// Whether an opt-out covers `ev` for `entry` (VTI-EVT-110).
///
/// # Errors
/// A store failure.
pub async fn opted_out(
    ks: &KeyspaceHandle,
    entry: &str,
    ev: &EventRecord,
) -> Result<bool, AppError> {
    Ok(ks
        .get_raw(opt_key(entry, "event", &ev.event_id))
        .await?
        .is_some()
        || ks
            .get_raw(opt_key(entry, "calendar", &ev.calendar_id))
            .await?
            .is_some())
}

/// `EventOptOut` as the wire states it.
#[must_use]
pub fn opt_out_wire(o: &OptOut) -> Value {
    let mut v = json!({ "scope": o.scope, "createdAt": stamp(o.created_at) });
    v[if o.scope == "event" {
        "eventId"
    } else {
        "calendarId"
    }] = json!(o.id);
    v
}

// ── announcements ──

/// # Errors
/// A store failure.
pub async fn put_announcement(ks: &KeyspaceHandle, a: &Announcement) -> Result<(), AppError> {
    ks.insert(ann_key(&a.event_id, &a.announcement_id), a).await
}

/// An event's announcements, newest first.
///
/// # Errors
/// A store failure.
pub async fn announcements_of(
    ks: &KeyspaceHandle,
    event: &str,
) -> Result<Vec<Announcement>, AppError> {
    let mut all: Vec<Announcement> = values(ks, &format!("ann:{event}:")).await?;
    all.sort_by(|a, b| (b.created_at, &b.announcement_id).cmp(&(a.created_at, &a.announcement_id)));
    Ok(all)
}

/// `EventAnnouncement` as the wire states it.
#[must_use]
pub fn announcement_wire(a: &Announcement) -> Value {
    let mut o = Map::new();
    o.insert("announcementId".into(), json!(a.announcement_id));
    o.insert("eventId".into(), json!(a.event_id));
    o.insert("text".into(), json!(a.text));
    if let Some(p) = &a.posted_by {
        o.insert("postedBy".into(), json!(p));
    }
    o.insert("createdAt".into(), json!(stamp(a.created_at)));
    Value::Object(o)
}

// ── wire ──

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// `EventInvitation`; `inviterEntryId` only for hosts (VTI-EVT-106).
#[must_use]
pub fn invitation_wire(i: &Invitation, host_view: bool) -> Value {
    let mut o = Map::new();
    o.insert("invitationId".into(), json!(i.invitation_id));
    o.insert("eventId".into(), json!(i.event_id));
    o.insert("entryId".into(), json!(i.entry_id));
    o.insert("invitedBy".into(), json!(i.invited_by.as_str()));
    if host_view && let Some(e) = &i.inviter_entry_id {
        o.insert("inviterEntryId".into(), json!(e));
    }
    o.insert("replyExpected".into(), json!(i.reply_expected));
    o.insert("answer".into(), json!(i.answer.as_str()));
    if let Some(t) = i.answered_at {
        o.insert("answeredAt".into(), json!(stamp(t)));
    }
    if i.revoked {
        o.insert("revoked".into(), json!(true));
    }
    o.insert("createdAt".into(), json!(stamp(i.created_at)));
    Value::Object(o)
}

/// `EventInvitationLink`, never with its code.
#[must_use]
pub fn link_wire(l: &Link) -> Value {
    let mut o = Map::new();
    o.insert("linkId".into(), json!(l.link_id));
    o.insert("eventId".into(), json!(l.event_id));
    if let Some(x) = &l.label {
        o.insert("label".into(), json!(x));
    }
    o.insert("maxRedemptions".into(), json!(l.max_redemptions));
    o.insert("redemptions".into(), json!(l.redemptions));
    o.insert("expiresAt".into(), json!(stamp(l.expires_at)));
    if let Some(t) = l.revoked_at {
        o.insert("revokedAt".into(), json!(stamp(t)));
    }
    o.insert("createdAt".into(), json!(stamp(l.created_at)));
    Value::Object(o)
}

// ─── the `event` notification (VTI-NTF-064 – 067) ────────────────────────

/// The `notifications/notify/0.1` payload for `notice` about `ev`, to `audience`: the
/// community as holder, the event's identifier, the task that opens it, the audience and the
/// event's period — and nothing else of the event (VTI-NTF-003, VTI-NTF-064).
#[must_use]
pub fn payload(community: &str, ev: &EventRecord, audience: &str, notice: &Notice) -> Value {
    let mut n = json!({
        "notificationId": notice.notification_id,
        "revision": notice.revision,
        "kind": KIND_EVENT,
        "subject": {
            "heldBy": community,
            "id": ev.event_id,
            "openWith": EVENT_OPEN_WITH,
        },
        "audience": audience,
        "status": if notice.withdrawn { "withdrawn" } else { "available" },
        "relayable": true,
    });
    if let Ok((start, end)) = ev.interval() {
        n["validFrom"] = json!(stamp(start));
        n["validUntil"] = json!(stamp(end));
    }
    json!({ "notification": n })
}

/// Bring `notice` in step with `ev`: a withdrawal when `withdraw`, else a new revision when the
/// event's sequence moved (VTI-NTF-065). `true` when it changed.
fn advance(notice: &mut Notice, ev: &EventRecord, withdraw: bool) -> bool {
    if notice.withdrawn {
        return false;
    }
    if withdraw {
        notice.revision += 1;
        notice.withdrawn = true;
        return true;
    }
    if notice.sequence != ev.sequence {
        notice.revision += 1;
        notice.sequence = ev.sequence;
        return true;
    }
    false
}

/// Whether `partner` is a community this one may name as a partner (VTI-EVT-130): an active
/// member holding an unrevoked membership credential of ours, or a party with which this
/// community holds a relationship in force.
///
/// # Errors
/// A store failure.
pub async fn partner_valid(state: &AppState, partner: &str) -> Result<bool, AppError> {
    if let Some(active) = crate::member_portal::active::active_member(state, partner).await?
        && active.member.current_vmc_id.is_some()
    {
        let revoked = match active.member.status_list_index {
            Some(slot) => crate::status_list::get_state(
                &state.status_lists_ks,
                affinidi_status_list::StatusPurpose::Revocation,
            )
            .await?
            .is_some_and(|r| r.is_set(slot as usize)),
            None => false,
        };
        if !revoked {
            return Ok(true);
        }
    }
    let Some(community) = crate::notifications::own_did(state).await else {
        return Ok(false);
    };
    Ok(crate::relationships::storage::counterparties_in_force(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &community,
        Utc::now(),
    )
    .await?
    .contains(partner))
}

/// The partner communities `ev`'s audience names.
#[must_use]
pub fn partners(ev: &EventRecord) -> Vec<String> {
    ev.audience
        .get("partners")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Queue `notice` to `to` if a revision is not yet queued. An offering revision is queued only
/// when `concerned` (VTI-NTF-005). `true` when it queued one.
async fn send(
    state: &AppState,
    community: &str,
    ev: &EventRecord,
    to: &str,
    notice: &mut Notice,
    concerned: bool,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    if notice.queued_revision >= notice.revision || (!notice.withdrawn && !concerned) {
        return Ok(false);
    }
    let until = ev.interval().ok().map(|(_, end)| end);
    crate::notifications::push_signed(
        state,
        to,
        TASK_NOTIFICATIONS_NOTIFY_0_1,
        payload(community, ev, to, notice),
        crate::notifications::deliver_by(until, now, std::time::Duration::from_secs(3600)),
    )
    .await?;
    notice.queued_revision = notice.revision;
    Ok(true)
}

/// Whether `entry`/`did` is still in `ev`'s audience: an active member the audience admits, or
/// one a standing host or link invitation admits (VTI-EVT-103).
async fn still_in_audience(
    state: &AppState,
    ev: &EventRecord,
    inv: &Invitation,
    schema: &[crate::directory::model::FieldDef],
) -> Result<bool, AppError> {
    let Some(subject) = crate::directory::read::subject_by_entry(state, &inv.entry_id).await?
    else {
        return Ok(false);
    };
    if !subject.active {
        return Ok(false);
    }
    Ok(inv.widens() || super::audience_admits(&ev.audience, &subject, schema))
}

/// One pass of the one sender (module docs). Failures to queue one recipient's revision are
/// logged and retried on the next pass; they never stop the others.
///
/// # Errors
/// A store failure.
pub async fn settle(state: &AppState, now: DateTime<Utc>) -> Result<(), AppError> {
    let Some(community) = crate::notifications::own_did(state).await else {
        return Ok(());
    };
    let ks = &state.events_ks;
    let schema = crate::directory::fields::schema(state.directory.ks()).await?;
    let mut subjects = None;
    for ev in super::events(ks).await? {
        if ev.status == Lifecycle::Draft || ev.ended(now) {
            continue;
        }
        let cancelled = ev.status == Lifecycle::Cancelled;
        // 1. Invite the audience (VTI-EVT-101, VTI-EVT-108).
        if !cancelled && ev.invite != InviteMode::None {
            if subjects.is_none() {
                subjects = Some(crate::directory::read::subjects(state).await?);
            }
            let _guard = super::WRITE_LOCK.lock().await;
            let registered: BTreeSet<String> = super::registrations_of(ks, &ev.event_id)
                .await?
                .into_iter()
                .map(|r| r.entry_id)
                .collect();
            for s in subjects.as_deref().unwrap_or_default() {
                let entry = &s.card.entry_id;
                if !s.active
                    || registered.contains(entry)
                    || !super::audience_admits(&ev.audience, s, &schema)
                    || get_invitation(ks, &ev.event_id, entry).await?.is_some()
                    || opted_out(ks, entry, &ev).await?
                {
                    continue;
                }
                invite(ks, &ev, entry, &s.card.did, Inviter::Audience, None, now).await?;
            }
        }
        // 2 – 3. Keep every invitation's notification in step, and send.
        for mut inv in invitations_of(ks, &ev.event_id).await? {
            let in_audience = still_in_audience(state, &ev, &inv, &schema).await?;
            let mut changed = advance(
                &mut inv.notice,
                &ev,
                cancelled || inv.revoked || !in_audience,
            );
            match send(
                state,
                &community,
                &ev,
                &inv.did,
                &mut inv.notice,
                in_audience,
                now,
            )
            .await
            {
                Ok(sent) => changed |= sent,
                Err(e) => {
                    tracing::warn!(event = %ev.event_id, error = %e, "an event invitation could not be queued; the next pass tries again")
                }
            }
            if changed {
                put_invitation(ks, &inv).await?;
            }
        }
        // VTI-EVT-131: one notification to each partner the audience names, at its own DID.
        for partner in partners(&ev) {
            let key = pnotice_key(&ev.event_id, &partner);
            let mut pn = match ks.get::<PartnerNotice>(key.clone()).await? {
                Some(p) => p,
                None if cancelled => continue,
                None => {
                    let p = PartnerNotice {
                        event_id: ev.event_id.clone(),
                        partner: partner.clone(),
                        notice: Notice::new(ev.sequence),
                    };
                    ks.insert(key.clone(), &p).await?;
                    p
                }
            };
            let valid = partner_valid(state, &partner).await?;
            let mut changed = advance(&mut pn.notice, &ev, cancelled);
            match send(state, &community, &ev, &partner, &mut pn.notice, valid, now).await {
                Ok(sent) => changed |= sent,
                Err(e) => {
                    tracing::warn!(event = %ev.event_id, error = %e, "an event notification to a partner could not be queued; the next pass tries again")
                }
            }
            if changed {
                ks.insert(key, &pn).await?;
            }
        }
    }
    Ok(())
}

/// The partner notices sent for `event`, for tests and the console.
///
/// # Errors
/// A store failure.
pub async fn partner_notices(
    ks: &KeyspaceHandle,
    event: &str,
) -> Result<Vec<PartnerNotice>, AppError> {
    values(ks, &format!("pnotice:{event}:")).await
}

/// The day a daily limit counts back to.
#[must_use]
pub fn a_day_before(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::days(1)
}
