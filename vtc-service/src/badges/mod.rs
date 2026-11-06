//! Member badges (`vtc/badges/*`, VTI Community Badges chapter, VTI-BDG-001 – 095).
//!
//! A badge is a picture with a name a member earns, holds and shows on their directory
//! card. **A community badge is a badge group**: creating one creates a community group
//! (`crate::groups`) that backs it — its managers are the badge's owners, its members the
//! holders, and the group's own DID issues each holder the badge credential
//! ([`credential`]) in place of a group membership credential. A **kudos badge** has no
//! group and no credential: any active member gives it to any other, and each giving is
//! counted.
//!
//! **An award is an offer until accepted** (VTI-BDG-020). Giving a badge records an
//! [`Award`] in state `offered`; nothing is admitted to any group, issued or shown until
//! the recipient accepts it (`vtc/badges/mine/accept`), and a decline records nothing in
//! any group. **Hidden is portal-only** (VTI-BDG-030): a holder who hides a badge keeps
//! its awards, membership and credential; the badge leaves their wall, the holder list
//! shown to members, and the counts, while owners and administrators see the holder
//! marked hidden. **Badges confer nothing** (VTI-BDG-002): nothing here is read by an
//! authorization decision.
//!
//! Records live in the `badges` keyspace (backed up): the community's settings
//! (`settings`), each badge (`badge:<badgeId>`), each award (`award:<awardId>`, indexed
//! `bawd:<badgeId>:<awardId>` and `eawd:<entryId>:<awardId>`, with a giver index
//! `gawd:<entryId>:<awardId>`), and each holder's own preferences (`prefs:<entryId>`:
//! hidden set, pins, order, wall visibility). Pictures live in `badge_images`, through the
//! directory's picture pipeline (`crate::directory::images`): re-encoded, never a byte as
//! sent. The badge group, its DID, its authority credential and its memberships are the
//! groups subsystem's.

pub mod credential;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

/// Every write to the `badges` keyspace that reads before it writes takes this lock,
/// so two offers of one badge to one member, or two accepts of one award, never race.
pub(crate) static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

#[must_use]
pub fn new_badge_id() -> String {
    new_id("bdg")
}

#[must_use]
pub fn new_award_id() -> String {
    new_id("awd")
}

// ─── settings ────────────────────────────────────────────────────────────

/// Who may make a kudos badge (`KudosMakers`, VTI-BDG-004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KudosMakers {
    /// `nobody` | `roles` | `members`.
    pub policy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl Default for KudosMakers {
    fn default() -> Self {
        KudosMakers {
            policy: "members".into(),
            roles: Vec::new(),
            groups: Vec::new(),
        }
    }
}

/// The community's bounds (`BadgeLimits`). Each answers its default where unset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kudos_per_giver_per_day: Option<u32>,
    /// `day` | `week` | `unbounded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_giver_same_member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tenure_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kudos_badges_per_maker_per_month: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pinned: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_expires_after_days: Option<u32>,
}

impl Limits {
    pub fn kudos_per_giver_per_day(&self) -> u32 {
        self.kudos_per_giver_per_day.unwrap_or(10)
    }
    pub fn same_giver_same_member(&self) -> &str {
        self.same_giver_same_member.as_deref().unwrap_or("day")
    }
    pub fn min_tenure_days(&self) -> u32 {
        self.min_tenure_days.unwrap_or(7)
    }
    pub fn kudos_badges_per_maker_per_month(&self) -> u32 {
        self.kudos_badges_per_maker_per_month.unwrap_or(5)
    }
    pub fn max_pinned(&self) -> usize {
        self.max_pinned.unwrap_or(2) as usize
    }
}

/// The community's badge settings (`BadgeSettings`, VTI-BDG-004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub enabled: bool,
    #[serde(default)]
    pub kudos_makers: KudosMakers,
    #[serde(default)]
    pub limits: Limits,
    pub show_kudos_totals: bool,
    pub automatic_badges: bool,
    pub members_may_request: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_valid_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for Settings {
    /// Badges are off until an administrator turns them on.
    fn default() -> Self {
        Settings {
            enabled: false,
            kudos_makers: KudosMakers::default(),
            limits: Limits::default(),
            show_kudos_totals: true,
            automatic_badges: false,
            members_may_request: true,
            credential_valid_days: None,
            updated_at: None,
        }
    }
}

impl Settings {
    /// `BadgeSettings` on the wire.
    pub fn wire(&self) -> Value {
        let mut out = json!({
            "enabled": self.enabled,
            "kudosMakers": self.kudos_makers,
            "showKudosTotals": self.show_kudos_totals,
            "automaticBadges": self.automatic_badges,
            "membersMayRequest": self.members_may_request,
        });
        let limits = serde_json::to_value(&self.limits).unwrap_or(json!({}));
        if limits.as_object().is_some_and(|o| !o.is_empty()) {
            out["limits"] = limits;
        }
        if let Some(d) = self.credential_valid_days {
            out["credentialValidDays"] = json!(d);
        }
        if let Some(at) = self.updated_at {
            out["updatedAt"] = json!(at);
        }
        out
    }
}

const SETTINGS_KEY: &[u8] = b"settings";

pub async fn settings(ks: &KeyspaceHandle) -> Result<Settings, AppError> {
    Ok(ks
        .get::<Settings>(SETTINGS_KEY.to_vec())
        .await?
        .unwrap_or_default())
}

pub async fn put_settings(ks: &KeyspaceHandle, s: &Settings) -> Result<(), AppError> {
    ks.insert(SETTINGS_KEY.to_vec(), s).await
}

// ─── badges ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BadgeKind {
    Community,
    Kudos,
}

impl BadgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Community => "community",
            Self::Kudos => "kudos",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "community" => Some(Self::Community),
            "kudos" => Some(Self::Kudos),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BadgeState {
    Active,
    Retired,
}

impl BadgeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

/// One badge (`Badge`, VTI-BDG-001).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Badge {
    pub badge_id: String,
    pub kind: BadgeKind,
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criteria: Option<String>,
    /// The picture's `CardBlobRef`: `sha256`, `mediaType`, `size`.
    pub image: Value,
    pub repeatable: bool,
    #[serde(default)]
    pub requestable: bool,
    #[serde(default = "yes")]
    pub listed: bool,
    #[serde(default)]
    pub shareable_outside: bool,
    /// The badge group backing a community badge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub state: BadgeState,
    pub created_at: DateTime<Utc>,
    /// The maker's directory entry, where they have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

fn yes() -> bool {
    true
}

impl Badge {
    pub fn is_community(&self) -> bool {
        self.kind == BadgeKind::Community
    }

    pub fn is_active(&self) -> bool {
        self.state == BadgeState::Active
    }

    /// `Badge` on the wire, without `holderCount` (the caller adds it where the viewer
    /// may see the holders).
    pub fn wire(&self) -> Value {
        let mut out = json!({
            "badgeId": self.badge_id,
            "kind": self.kind.as_str(),
            "name": self.name,
            "description": self.description,
            "image": self.image,
            "repeatable": self.repeatable,
            "listed": self.listed,
            "state": self.state.as_str(),
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        });
        if let Some(c) = &self.criteria {
            out["criteria"] = json!(c);
        }
        if self.is_community() {
            out["requestable"] = json!(self.requestable);
            out["shareableOutside"] = json!(self.shareable_outside);
            if let Some(g) = &self.group_id {
                out["groupId"] = json!(g);
            }
        }
        if let Some(by) = &self.created_by {
            out["createdBy"] = json!(by);
        }
        if let Some(at) = self.retired_at {
            out["retiredAt"] = json!(at);
        }
        out
    }
}

fn badge_key(badge_id: &str) -> Vec<u8> {
    format!("badge:{badge_id}").into_bytes()
}

pub async fn get_badge(ks: &KeyspaceHandle, badge_id: &str) -> Result<Option<Badge>, AppError> {
    ks.get(badge_key(badge_id)).await
}

pub async fn put_badge(ks: &KeyspaceHandle, badge: &Badge) -> Result<(), AppError> {
    ks.insert(badge_key(&badge.badge_id), badge).await
}

pub async fn all_badges(ks: &KeyspaceHandle) -> Result<Vec<Badge>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(b"badge:".to_vec()).await? {
        if let Ok(b) = serde_json::from_slice::<Badge>(&raw) {
            out.push(b);
        }
    }
    out.sort_by_key(|b| b.name.to_lowercase());
    Ok(out)
}

/// The badge whose group is `group_id`, if any.
pub async fn badge_of_group(
    ks: &KeyspaceHandle,
    group_id: &str,
) -> Result<Option<Badge>, AppError> {
    Ok(all_badges(ks)
        .await?
        .into_iter()
        .find(|b| b.group_id.as_deref() == Some(group_id)))
}

/// Whether the picture `sha` is held by a badge other than `except`.
pub async fn image_held(
    ks: &KeyspaceHandle,
    sha: &str,
    except: Option<&str>,
) -> Result<bool, AppError> {
    Ok(all_badges(ks).await?.iter().any(|b| {
        Some(b.badge_id.as_str()) != except
            && crate::directory::images::sha_of(&b.image) == Some(sha)
    }))
}

/// The pictures every badge holds, by digest.
pub async fn images_held(ks: &KeyspaceHandle) -> Result<BTreeSet<String>, AppError> {
    Ok(all_badges(ks)
        .await?
        .iter()
        .filter_map(|b| crate::directory::images::sha_of(&b.image).map(str::to_string))
        .collect())
}

// ─── awards ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AwardState {
    Offered,
    Accepted,
    Declined,
    Withdrawn,
    Expired,
    Revoked,
}

impl AwardState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "offered" => Self::Offered,
            "accepted" => Self::Accepted,
            "declined" => Self::Declined,
            "withdrawn" => Self::Withdrawn,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => return None,
        })
    }
}

/// One giving of a badge to one member (`Award`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Award {
    pub award_id: String,
    pub badge_id: String,
    /// The recipient.
    pub entry_id: String,
    /// The giver's entry; absent for an award a rule made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub state: AwardState,
    pub offered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// A take-back's reason: the owner's, kept for the audit trail, never shown to the
    /// holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
}

impl Award {
    pub fn is_open(&self) -> bool {
        self.state == AwardState::Offered
    }

    pub fn is_accepted(&self) -> bool {
        self.state == AwardState::Accepted
    }

    /// `Award` on the wire: the note goes to the recipient, the giver, the badge's owners
    /// and administrators only (`with_note`).
    pub fn wire(&self, with_note: bool) -> Value {
        let mut out = json!({
            "awardId": self.award_id,
            "badgeId": self.badge_id,
            "entryId": self.entry_id,
            "state": self.state.as_str(),
            "offeredAt": self.offered_at,
        });
        if let Some(by) = &self.given_by {
            out["givenBy"] = json!(by);
        }
        if with_note && let Some(n) = &self.note {
            out["note"] = json!(n);
        }
        if let Some(at) = self.decided_at {
            out["decidedAt"] = json!(at);
        }
        if let Some(at) = self.expires_at {
            out["expiresAt"] = json!(at);
        }
        if let Some(c) = &self.credential_id {
            out["credentialId"] = json!(c);
        }
        out
    }
}

fn award_key(award_id: &str) -> Vec<u8> {
    format!("award:{award_id}").into_bytes()
}
fn by_badge_key(badge_id: &str, award_id: &str) -> Vec<u8> {
    format!("bawd:{badge_id}:{award_id}").into_bytes()
}
fn by_entry_key(entry_id: &str, award_id: &str) -> Vec<u8> {
    format!("eawd:{entry_id}:{award_id}").into_bytes()
}
fn by_giver_key(entry_id: &str, award_id: &str) -> Vec<u8> {
    format!("gawd:{entry_id}:{award_id}").into_bytes()
}

pub async fn get_award(ks: &KeyspaceHandle, award_id: &str) -> Result<Option<Award>, AppError> {
    ks.get(award_key(award_id)).await
}

/// Store an award and its indexes.
pub async fn put_award(ks: &KeyspaceHandle, a: &Award) -> Result<(), AppError> {
    let mut batch = Batch::new();
    batch
        .insert(award_key(&a.award_id), a)?
        .insert_raw(by_badge_key(&a.badge_id, &a.award_id), Vec::new())
        .insert_raw(by_entry_key(&a.entry_id, &a.award_id), Vec::new());
    if let Some(g) = &a.given_by {
        batch.insert_raw(by_giver_key(g, &a.award_id), Vec::new());
    }
    ks.apply_batch(batch).await.map(drop)
}

async fn awards_by_index(
    ks: &KeyspaceHandle,
    prefix: Vec<u8>,
    split: usize,
) -> Result<Vec<Award>, AppError> {
    let mut out = Vec::new();
    for (key, _) in ks.prefix_iter_raw(prefix).await? {
        let key = String::from_utf8_lossy(&key);
        let Some(award_id) = key.splitn(split, ':').nth(split - 1) else {
            continue;
        };
        if let Some(a) = get_award(ks, award_id).await? {
            out.push(a);
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.offered_at));
    Ok(out)
}

/// Every award of `badge_id`, newest first.
pub async fn awards_of_badge(ks: &KeyspaceHandle, badge_id: &str) -> Result<Vec<Award>, AppError> {
    awards_by_index(ks, format!("bawd:{badge_id}:").into_bytes(), 3).await
}

/// Every award to `entry_id`, newest first.
pub async fn awards_to(ks: &KeyspaceHandle, entry_id: &str) -> Result<Vec<Award>, AppError> {
    awards_by_index(ks, format!("eawd:{entry_id}:").into_bytes(), 3).await
}

/// Every award `entry_id` gave, newest first.
pub async fn awards_given_by(ks: &KeyspaceHandle, entry_id: &str) -> Result<Vec<Award>, AppError> {
    awards_by_index(ks, format!("gawd:{entry_id}:").into_bytes(), 3).await
}

/// The accepted awards of `badge_id` held by `entry_id`, oldest first (the credential's
/// evidence order).
pub async fn accepted_of(
    ks: &KeyspaceHandle,
    badge_id: &str,
    entry_id: &str,
) -> Result<Vec<Award>, AppError> {
    let mut out: Vec<Award> = awards_to(ks, entry_id)
        .await?
        .into_iter()
        .filter(|a| a.badge_id == badge_id && a.is_accepted())
        .collect();
    out.sort_by_key(|a| a.decided_at);
    Ok(out)
}

/// A holder's standing in one badge: how many accepted awards, since when, the latest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holding {
    pub badge_id: String,
    pub count: usize,
    pub since: DateTime<Utc>,
    pub latest_at: DateTime<Utc>,
    pub credential_id: Option<String>,
}

/// What `entry_id` holds, by badge, from their accepted awards.
pub async fn holdings_of(
    ks: &KeyspaceHandle,
    entry_id: &str,
) -> Result<BTreeMap<String, Holding>, AppError> {
    let mut out: BTreeMap<String, Holding> = BTreeMap::new();
    for a in awards_to(ks, entry_id).await? {
        if !a.is_accepted() {
            continue;
        }
        let at = a.decided_at.unwrap_or(a.offered_at);
        let h = out.entry(a.badge_id.clone()).or_insert_with(|| Holding {
            badge_id: a.badge_id.clone(),
            count: 0,
            since: at,
            latest_at: at,
            credential_id: None,
        });
        h.count += 1;
        h.since = h.since.min(at);
        if at >= h.latest_at {
            h.latest_at = at;
            if a.credential_id.is_some() {
                h.credential_id = a.credential_id.clone();
            }
        }
    }
    Ok(out)
}

/// Mark every open offer of `badge_id` `withdrawn` (retire item 5); how many.
pub async fn withdraw_open_offers(
    ks: &KeyspaceHandle,
    badge_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let mut n = 0;
    for mut a in awards_of_badge(ks, badge_id).await? {
        if a.is_open() {
            a.state = AwardState::Withdrawn;
            a.decided_at = Some(now);
            put_award(ks, &a).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// Expire every offer whose `expiresAt` has passed; how many.
pub async fn expire_offers(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let _guard = WRITE_LOCK.lock().await;
    let mut n = 0;
    for (_, raw) in ks.prefix_iter_raw(b"award:".to_vec()).await? {
        let Ok(mut a) = serde_json::from_slice::<Award>(&raw) else {
            continue;
        };
        if a.is_open() && a.expires_at.is_some_and(|at| at <= now) {
            a.state = AwardState::Expired;
            a.decided_at = Some(now);
            put_award(ks, &a).await?;
            n += 1;
        }
    }
    Ok(n)
}

// ─── the holder's preferences ────────────────────────────────────────────

/// A holder's own choices (VTI-BDG-030 – 032): what they hid, pinned, their order, and
/// who sees their wall. Never a record of what they hold — that is their awards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prefs {
    pub entry_id: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub hidden: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
    /// `members` | `nobody`.
    #[serde(default = "members")]
    pub visibility: String,
}

fn members() -> String {
    "members".into()
}

impl Prefs {
    pub fn new(entry_id: &str) -> Self {
        Prefs {
            entry_id: entry_id.to_string(),
            hidden: BTreeSet::new(),
            pinned: Vec::new(),
            order: Vec::new(),
            visibility: members(),
        }
    }

    pub fn is_hidden(&self, badge_id: &str) -> bool {
        self.hidden.contains(badge_id)
    }

    pub fn is_pinned(&self, badge_id: &str) -> bool {
        self.pinned.iter().any(|b| b == badge_id)
    }

    /// The holder's wall order: pinned first, then their order, then anything they hold
    /// that neither names, in `held`'s order.
    pub fn arrange<'a>(&self, held: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        let held: Vec<&str> = held.into_iter().collect();
        let mut out: Vec<String> = Vec::with_capacity(held.len());
        let mut push = |id: &str| {
            if held.contains(&id) && !out.iter().any(|o| o == id) {
                out.push(id.to_string());
            }
        };
        for id in &self.pinned {
            push(id);
        }
        for id in &self.order {
            push(id);
        }
        for id in &held {
            push(id);
        }
        out
    }
}

fn prefs_key(entry_id: &str) -> Vec<u8> {
    format!("prefs:{entry_id}").into_bytes()
}

pub async fn prefs(ks: &KeyspaceHandle, entry_id: &str) -> Result<Prefs, AppError> {
    Ok(ks
        .get::<Prefs>(prefs_key(entry_id))
        .await?
        .unwrap_or_else(|| Prefs::new(entry_id)))
}

pub async fn put_prefs(ks: &KeyspaceHandle, p: &Prefs) -> Result<(), AppError> {
    ks.insert(prefs_key(&p.entry_id), p).await
}

/// The holders of `badge_id` who show it — their accepted awards summarised — newest
/// `latestAt` first, hidden holders left out (VTI-BDG-033).
pub async fn shown_holders(
    ks: &KeyspaceHandle,
    badge_id: &str,
) -> Result<Vec<(String, Holding)>, AppError> {
    let mut by_entry: BTreeMap<String, Holding> = BTreeMap::new();
    for a in awards_of_badge(ks, badge_id).await? {
        if !a.is_accepted() {
            continue;
        }
        let at = a.decided_at.unwrap_or(a.offered_at);
        let h = by_entry
            .entry(a.entry_id.clone())
            .or_insert_with(|| Holding {
                badge_id: badge_id.to_string(),
                count: 0,
                since: at,
                latest_at: at,
                credential_id: None,
            });
        h.count += 1;
        h.since = h.since.min(at);
        h.latest_at = h.latest_at.max(at);
    }
    let mut out = Vec::new();
    for (entry_id, h) in by_entry {
        if prefs(ks, &entry_id).await?.is_hidden(badge_id) {
            continue;
        }
        out.push((entry_id, h));
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.1.latest_at));
    Ok(out)
}

/// A member's kudos total (VTI-BDG-043): accepted, not hidden kudos awards.
pub async fn kudos_total(
    ks: &KeyspaceHandle,
    entry_id: &str,
    badges: &[Badge],
) -> Result<usize, AppError> {
    let p = prefs(ks, entry_id).await?;
    let kudos: BTreeSet<&str> = badges
        .iter()
        .filter(|b| b.kind == BadgeKind::Kudos)
        .map(|b| b.badge_id.as_str())
        .collect();
    Ok(awards_to(ks, entry_id)
        .await?
        .iter()
        .filter(|a| {
            a.is_accepted() && kudos.contains(a.badge_id.as_str()) && !p.is_hidden(&a.badge_id)
        })
        .count())
}

// ─── departure ───────────────────────────────────────────────────────────

/// A member's departure (VTI-BDG-090): their open offers are withdrawn, their preferences
/// go, and the awards they gave stand by entry reference. Their badge-group memberships
/// end with the groups' own departure handling. Returns how many offers were withdrawn.
pub async fn on_departure(ks: &KeyspaceHandle, entry_id: &str) -> Result<usize, AppError> {
    let _guard = WRITE_LOCK.lock().await;
    let now = Utc::now();
    let mut n = 0;
    for mut a in awards_to(ks, entry_id).await? {
        if a.is_open() {
            a.state = AwardState::Withdrawn;
            a.decided_at = Some(now);
            put_award(ks, &a).await?;
            n += 1;
        }
    }
    ks.remove(prefs_key(entry_id)).await?;
    Ok(n)
}

/// Erasure removes the text a member wrote on awards (VTI-BDG-090).
pub async fn erase_notes_by(ks: &KeyspaceHandle, entry_id: &str) -> Result<usize, AppError> {
    let _guard = WRITE_LOCK.lock().await;
    let mut n = 0;
    for mut a in awards_given_by(ks, entry_id).await? {
        if a.note.take().is_some() {
            put_award(ks, &a).await?;
            n += 1;
        }
    }
    Ok(n)
}

// ─── pictures ────────────────────────────────────────────────────────────

/// Erase lapsed uploads and pictures no badge holds (`images/upload` item 6), in the
/// `badge_images` keyspace. Returns how many pictures were erased.
pub async fn collect_images(
    images: &KeyspaceHandle,
    badges: &KeyspaceHandle,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let kept = images_held(badges).await?;
    crate::directory::images::collect_except(images, &kept, now).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrange_puts_pins_first_then_order_then_the_rest() {
        let mut p = Prefs::new("dir_a");
        p.pinned = vec!["b".into()];
        p.order = vec!["c".into(), "b".into(), "zz".into()];
        let out = p.arrange(["a", "b", "c", "d"]);
        assert_eq!(out, vec!["b", "c", "a", "d"]);
    }

    #[test]
    fn settings_default_to_off_with_the_specified_limits() {
        let s = Settings::default();
        assert!(!s.enabled);
        assert_eq!(s.limits.kudos_per_giver_per_day(), 10);
        assert_eq!(s.limits.same_giver_same_member(), "day");
        assert_eq!(s.limits.min_tenure_days(), 7);
        assert_eq!(s.limits.max_pinned(), 2);
        let w = s.wire();
        assert_eq!(w["kudosMakers"]["policy"], "members");
        assert!(w.get("limits").is_none());
    }
}
