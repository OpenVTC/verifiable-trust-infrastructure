//! Notifications addressed to this community, and relaying them to its members
//! (VTI-NTF-022 – 034, VTI-NTF-040 – 047, VTI-NTF-070 – 074).
//!
//! # The stated acceptance policy (VTI-NTF-030, VTI-NTF-034)
//!
//! A verified notification is held when the party that delivered it — the originator, or for a
//! relay the last relayer (VTI-NTF-031) — holds a live ACL entry at this community, is a party
//! to a relationship credential in force with the community's own DID, or is a network this
//! community is itself a member of by its own record (an **acknowledged** membership; a listing
//! the community never acknowledged does not count). Everything else is declined, and answered
//! with the same receipt (VTI-NTF-023).
//!
//! # The administrators' view (VTI-NTF-070)
//!
//! Holders of `vtc.notifications.read` list ([`list_page`]) and read ([`get`]) what is held,
//! with whether it may be relayed ([`ReceivedNotification::may_relay`]), what a relay of it
//! discloses ([`disclosure`]) and the decisions already made. Nobody else learns of it, members
//! included, except by a relay.
//!
//! # Relaying (VTI-NTF-071 – 073)
//!
//! Nothing is relayed by itself. An administrator holding `vtc.notifications.relay` decides a
//! relay ([`relay`]) to a [`Selection`] — all members, one group's, or one role's — resolved
//! from the community's own records at the decision to members whose membership is active,
//! less this community, the originator, every relayer the received chain names (VTI-NTF-047)
//! and every party already relayed to. A decision that has not acknowledged what the relay
//! discloses is refused (VTI-NTF-046). A relay carries the document this community received
//! **exactly as received** (VTI-NTF-041), one `notifications/relay/0.1` per member, queued on the
//! durable member push, and is made only while the community's own relay keeps the chain at
//! [`MAX_RELAYS`] or fewer. The record of whom it was relayed to is kept until the
//! notification's period ends — or, with no period, for [`RELAY_RECORD_DAYS`] — and used for
//! nothing but relaying later revisions to the same members, a withdrawal included
//! (VTI-NTF-044): [`settle`] does that, once a minute, and is the one retry owner. Each decision
//! records its selection and count, never whom it reached (VTI-NTF-073).
//!
//! Nothing reports to the originator whom a notification was relayed to (VTI-NTF-043).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vta_sdk::notifications::{MAX_RELAYS, VerifiedDelivery, identity, relay_disclosure};
use vta_sdk::trust_tasks::TASK_NOTIFICATIONS_RELAY_0_1;

use crate::error::AppError;
use crate::server::AppState;

/// How long the relay record of a notification that states no period is kept (VTI-NTF-044):
/// the period this community states and applies to every such notification.
pub const RELAY_RECORD_DAYS: i64 = 30;
/// The most notifications held from one originator, and delivered by one party (VTI-NTF-033).
pub const MAX_PER_PARTY: usize = 256;
/// The page `list_page` returns when the caller names no `limit`, and the most it returns.
pub const LIST_DEFAULT_PAGE: usize = 50;
pub const LIST_MAX_PAGE: usize = 200;

const RECORD_PREFIX: &str = "ntf:";
const DEDUP_PREFIX: &str = "dedup:";

/// Serialises writes: dedup-then-write is one critical section.
static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One member a notification was relayed to, and the revision last queued for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayedTo {
    pub did: String,
    pub revision: u64,
}

/// Which members a relay decision reaches (`vtc/notifications/_shared/0.1` `Recipients`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "scope",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Selection {
    /// Every active member.
    AllMembers,
    /// The active members of one community group.
    Group { group_id: String },
    /// The active members holding one community role, in the wire form member records use.
    Role { role: String },
}

impl Selection {
    /// The `scope` member's value.
    #[must_use]
    pub fn scope(&self) -> &'static str {
        match self {
            Selection::AllMembers => "allMembers",
            Selection::Group { .. } => "group",
            Selection::Role { .. } => "role",
        }
    }
}

/// One administrator's relay decision, as the community records it (VTI-NTF-073).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDecision {
    pub decided_at: DateTime<Utc>,
    pub decided_by: String,
    pub recipients: Selection,
    /// How many parties the decision added. Never who they are.
    pub recipient_count: usize,
    /// The revision held when it was decided.
    pub revision: u64,
    pub disclosure_acknowledged: bool,
}

/// A notification this community holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedNotification {
    pub record_id: String,
    pub originator: String,
    pub relayed_by: Vec<String>,
    pub delivered_by: String,
    /// The notification's members as the originator signed them.
    pub notification: Value,
    pub revision: u64,
    pub kind: String,
    pub relayable: bool,
    pub withdrawn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub received_at: DateTime<Utc>,
    /// The delivering document, exactly as received: what a relay carries.
    pub document: Value,
    /// The relay decisions made, oldest first.
    #[serde(default)]
    pub relay_decisions: Vec<RelayDecision>,
    /// Whom it was relayed to (VTI-NTF-044). Used for nothing else.
    #[serde(default)]
    pub relayed_to: Vec<RelayedTo>,
    /// When the record, and with it the relay record, is discarded.
    pub keep_until: DateTime<Utc>,
}

impl ReceivedNotification {
    /// Withdrawn, or past its `validUntil`: nothing to tell members of.
    #[must_use]
    pub fn is_lapsed(&self, now: DateTime<Utc>) -> bool {
        self.withdrawn || self.valid_until.is_some_and(|u| u <= now)
    }

    /// Whether this community may relay the revision held now: its originator says it may be
    /// relayed, its kind may be, the chain it arrived by carries at most `MAX_RELAYS - 1`
    /// relays so that this community's own makes at most [`MAX_RELAYS`] (VTI-NTF-041), and it
    /// has not lapsed.
    #[must_use]
    pub fn may_relay(&self, now: DateTime<Utc>) -> bool {
        self.chain_admits_relay() && !self.is_lapsed(now)
    }

    /// [`Self::may_relay`] without the lapse: whatever the time, the chain and the originator
    /// allow this community's relay.
    #[must_use]
    pub fn chain_admits_relay(&self) -> bool {
        self.relayable
            && vta_sdk::notifications::kind_may_be_relayed(&self.kind)
            && self.relayed_by.len() < MAX_RELAYS
    }

    /// The DID holding the thing (`subject.heldBy`).
    #[must_use]
    pub fn held_by(&self) -> &str {
        self.notification["subject"]["heldBy"]
            .as_str()
            .unwrap_or_default()
    }

    /// The parties this community never relays the revision held to (VTI-NTF-047): the
    /// originator and every relayer the chain names. This community itself is left out by the
    /// caller, which knows its own DID.
    fn excluded(&self, did: &str) -> bool {
        let did = identity(did);
        identity(&self.originator) == did || self.relayed_by.iter().any(|r| identity(r) == did)
    }

    /// The record as `ReceivedNotification` (`vtc/notifications/_shared/0.1`).
    #[must_use]
    pub fn to_wire(&self, now: DateTime<Utc>) -> Value {
        let at = |t: &DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut v = json!({
            "recordId": self.record_id,
            "originator": self.originator,
            "relayedBy": self.relayed_by,
            "notification": self.notification,
            "receivedAt": at(&self.received_at),
            "mayRelay": self.may_relay(now),
            "relayDecisions": self.relay_decisions.iter().map(|d| json!({
                "decidedAt": at(&d.decided_at),
                "decidedBy": d.decided_by,
                "recipients": d.recipients,
                "recipientCount": d.recipient_count,
            })).collect::<Vec<_>>(),
        });
        if let Some(statement) = disclosure(self) {
            v["relayDisclosure"] = json!(statement);
        }
        v
    }
}

fn digest(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

fn record_key(id: &str) -> String {
    format!("{RECORD_PREFIX}{id}")
}

fn dedup_key(originator: &str, notification_id: &str) -> String {
    format!(
        "{DEDUP_PREFIX}{}",
        digest(&[&identity(originator), notification_id])
    )
}

/// Every notification held, most recently received first (the record id breaks a tie, so
/// paging is total).
///
/// # Errors
/// A store failure.
pub async fn list(state: &AppState) -> Result<Vec<ReceivedNotification>, AppError> {
    let mut out: Vec<ReceivedNotification> = state
        .notifications_ks
        .prefix_iter_raw(RECORD_PREFIX)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    out.sort_by(|a, b| {
        b.received_at
            .cmp(&a.received_at)
            .then_with(|| b.record_id.cmp(&a.record_id))
    });
    Ok(out)
}

/// The filters of `vtc/notifications/list/0.1`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    pub kind: Option<String>,
    pub held_by: Option<String>,
    pub include_lapsed: bool,
}

impl ListFilter {
    fn digest(&self) -> String {
        digest(&[
            self.kind.as_deref().unwrap_or(""),
            self.held_by
                .as_deref()
                .map(identity)
                .as_deref()
                .unwrap_or(""),
            if self.include_lapsed { "l" } else { "" },
        ])[..16]
            .to_string()
    }

    fn admits(&self, rec: &ReceivedNotification, now: DateTime<Utc>) -> bool {
        self.kind.as_deref().is_none_or(|k| rec.kind == k)
            && self
                .held_by
                .as_deref()
                .is_none_or(|h| identity(h) == identity(rec.held_by()))
            && (self.include_lapsed || !rec.is_lapsed(now))
    }
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    f: String,
    t: DateTime<Utc>,
    r: String,
}

/// Why a list was refused.
#[derive(Debug)]
pub enum ListError {
    /// A cursor this community did not issue for these filters (`malformedRequest`).
    CursorInvalid,
    App(AppError),
}

impl From<AppError> for ListError {
    fn from(e: AppError) -> Self {
        ListError::App(e)
    }
}

/// `vtc/notifications/list/0.1`: one page of what `filter` admits, most recently received
/// first, and the cursor of the next page.
///
/// # Errors
/// See [`ListError`].
pub async fn list_page(
    state: &AppState,
    filter: &ListFilter,
    cursor: Option<&str>,
    limit: Option<usize>,
    now: DateTime<Utc>,
) -> Result<(Vec<ReceivedNotification>, Option<String>), ListError> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let fdigest = filter.digest();
    let after = match cursor {
        None => None,
        Some(c) => {
            let bytes = engine.decode(c).map_err(|_| ListError::CursorInvalid)?;
            let cur: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| ListError::CursorInvalid)?;
            if cur.f != fdigest {
                return Err(ListError::CursorInvalid);
            }
            Some((cur.t, cur.r))
        }
    };
    let limit = limit.unwrap_or(LIST_DEFAULT_PAGE).clamp(1, LIST_MAX_PAGE);
    let mut items: Vec<ReceivedNotification> = list(state)
        .await?
        .into_iter()
        .filter(|r| filter.admits(r, now))
        .collect();
    if let Some((t, r)) = after {
        items.retain(|x| (x.received_at, x.record_id.as_str()) < (t, r.as_str()));
    }
    let more = items.len() > limit;
    items.truncate(limit);
    let next = if more {
        items.last().map(|last| {
            let cur = Cursor {
                f: fdigest.clone(),
                t: last.received_at,
                r: last.record_id.clone(),
            };
            engine.encode(serde_json::to_vec(&cur).unwrap_or_default())
        })
    } else {
        None
    };
    Ok((items, next))
}

/// One held notification.
///
/// # Errors
/// A store failure.
pub async fn get(
    state: &AppState,
    record_id: &str,
) -> Result<Option<ReceivedNotification>, AppError> {
    state.notifications_ks.get(record_key(record_id)).await
}

/// The stated policy (VTI-NTF-034): whether `party` stands in a relationship with this
/// community — a live ACL entry here, a relationship credential in force with the community's
/// DID, or a network the community is itself a member of by its own record.
async fn has_standing(state: &AppState, party: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
    let party = identity(party);
    if let Some(entry) = crate::acl::storage::get_acl_entry(&state.acl_ks, &party).await?
        && !entry.is_expired(u64::try_from(now.timestamp()).unwrap_or(0))
    {
        return Ok(true);
    }
    // A membership the community entered and its own record holds as acknowledged. A listing
    // it never acknowledged, repudiated or left is not one (VTI-VTN-011).
    if crate::networks::list(state)
        .await?
        .iter()
        .any(|m| m.state == crate::networks::State::Acknowledged && identity(&m.network) == party)
    {
        return Ok(true);
    }
    let Some(own) = super::own_did(state).await else {
        return Ok(false);
    };
    let counterparties = crate::relationships::storage::counterparties_in_force(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &own,
        now,
    )
    .await?;
    Ok(counterparties.iter().any(|d| identity(d) == party))
}

/// What [`receive`] did — for logs and tests only; the answer never says (VTI-NTF-023).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Held { record_id: String },
    Replaced { record_id: String },
    Unchanged,
    Lapsed,
    NotAddressedHere,
    Declined,
    OverBound,
}

/// Hold `delivery` by the stated policy. A later revision of a notification already relayed is
/// relayed to the same members by the next [`settle`] (VTI-NTF-044).
///
/// # Errors
/// A store failure.
pub async fn receive(
    state: &AppState,
    delivery: &VerifiedDelivery,
    now: DateTime<Utc>,
) -> Result<Disposition, AppError> {
    let n = delivery.notification();
    if n.valid_until.is_some_and(|u| u <= now) {
        return Ok(Disposition::Lapsed);
    }
    match super::own_did(state).await {
        Some(own) if identity(&own) == identity(delivery.addressee()) => {}
        _ => return Ok(Disposition::NotAddressedHere),
    }
    if !has_standing(state, delivery.delivered_by(), now).await? {
        return Ok(Disposition::Declined);
    }
    let ks = &state.notifications_ks;
    let dkey = dedup_key(delivery.originator(), &n.notification_id);
    let withdrawn = matches!(
        n.status,
        vti_specs::notifications::notify::v0_1::Status::Withdrawn
    );
    let keep_until = n
        .valid_until
        .unwrap_or(now + chrono::Duration::days(RELAY_RECORD_DAYS));

    let _guard = WRITE_LOCK.lock().await;
    if let Some(record_id) = ks.get::<String>(dkey.clone()).await?
        && let Some(mut rec) = get(state, &record_id).await?
    {
        if n.revision.get() <= rec.revision {
            return Ok(Disposition::Unchanged);
        }
        rec.relayed_by = delivery.relayed_by().to_vec();
        rec.delivered_by = delivery.delivered_by().to_string();
        rec.notification = delivery.notification_json().clone();
        rec.revision = n.revision.get();
        rec.kind = n.kind.to_string();
        rec.relayable = n.relayable;
        rec.withdrawn = withdrawn;
        rec.valid_until = n.valid_until;
        rec.received_at = now;
        rec.document = delivery.document().clone();
        // A record is never shortened below what an earlier revision promised the members.
        rec.keep_until = rec.keep_until.max(keep_until);
        ks.insert(record_key(&record_id), &rec).await?;
        return Ok(Disposition::Replaced { record_id });
    }
    let all = list(state).await?;
    let from_originator = all
        .iter()
        .filter(|r| identity(&r.originator) == identity(delivery.originator()))
        .count();
    let from_deliverer = all
        .iter()
        .filter(|r| identity(&r.delivered_by) == identity(delivery.delivered_by()))
        .count();
    if from_originator >= MAX_PER_PARTY || from_deliverer >= MAX_PER_PARTY {
        return Ok(Disposition::OverBound);
    }
    let record_id = format!("rn-{}", uuid::Uuid::new_v4().simple());
    let rec = ReceivedNotification {
        record_id: record_id.clone(),
        originator: delivery.originator().to_string(),
        relayed_by: delivery.relayed_by().to_vec(),
        delivered_by: delivery.delivered_by().to_string(),
        notification: delivery.notification_json().clone(),
        revision: n.revision.get(),
        kind: n.kind.to_string(),
        relayable: n.relayable,
        withdrawn,
        valid_until: n.valid_until,
        received_at: now,
        document: delivery.document().clone(),
        relay_decisions: Vec::new(),
        relayed_to: Vec::new(),
        keep_until,
    };
    ks.insert(record_key(&record_id), &rec).await?;
    ks.insert(dkey, &record_id).await?;
    Ok(Disposition::Held { record_id })
}

/// Why a relay was refused.
#[derive(Debug)]
pub enum RelayError {
    /// No such held notification (`notificationUnknown`).
    Unknown,
    /// Its originator says it may not be relayed, its kind may not be, or the chain it arrived
    /// by already carries [`MAX_RELAYS`] relays (`notRelayable`, VTI-NTF-041).
    NotRelayable,
    /// It has lapsed or been withdrawn: there is nothing to tell members of (`lapsed`).
    Lapsed,
    /// The decision did not acknowledge what the relay discloses (VTI-NTF-046). Carries the
    /// statement to show (`disclosureNotAcknowledged`).
    DisclosureNotShown(&'static str),
    /// The group the selection names does not exist (`groupUnknown`).
    GroupUnknown,
    App(AppError),
}

impl From<AppError> for RelayError {
    fn from(e: AppError) -> Self {
        RelayError::App(e)
    }
}

/// What a relay of `rec` discloses about this community, to show whoever decides it.
#[must_use]
pub fn disclosure(rec: &ReceivedNotification) -> Option<&'static str> {
    relay_disclosure(&rec.kind)
}

/// What a decision did: the revision it relays and how many parties it added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayOutcome {
    pub revision: u64,
    pub recipient_count: usize,
}

/// The active members `selection` names, by DID, from the community's own records now
/// (VTI-NTF-072).
async fn resolve(state: &AppState, selection: &Selection) -> Result<Vec<String>, RelayError> {
    use crate::member_portal::active::active_member;
    let mut out = Vec::new();
    match selection {
        Selection::AllMembers | Selection::Role { .. } => {
            for m in crate::members::storage::list_members(&state.members_ks).await? {
                let Some(active) = active_member(state, &m.did).await? else {
                    continue;
                };
                if let Selection::Role { role } = selection
                    && active.entry.role.to_string() != *role
                {
                    continue;
                }
                out.push(m.did);
            }
        }
        Selection::Group { group_id } => {
            let ks = state.directory.ks();
            if crate::groups::get(ks, group_id).await?.is_none() {
                return Err(RelayError::GroupUnknown);
            }
            for m in crate::groups::members_of(ks, group_id).await? {
                if m.state != "active" {
                    continue;
                }
                let Some(card) = crate::directory::cards::get(ks, &m.entry_id).await? else {
                    continue;
                };
                if active_member(state, &card.did).await?.is_some() {
                    out.push(card.did);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// An administrator's decision to relay `record_id` to the members `selection` names
/// (VTI-NTF-071 – 073). Records the decision and the parties it added before anything is
/// queued, then queues one relay each. `disclosure_acknowledged` is the decider's statement
/// that they were shown [`disclosure`]. Who may decide which selection is the caller's check.
///
/// # Errors
/// See [`RelayError`].
pub async fn relay(
    state: &AppState,
    record_id: &str,
    decided_by: &str,
    selection: &Selection,
    disclosure_acknowledged: bool,
    now: DateTime<Utc>,
) -> Result<RelayOutcome, RelayError> {
    let (mut rec, added) = {
        let _guard = WRITE_LOCK.lock().await;
        let mut rec = get(state, record_id).await?.ok_or(RelayError::Unknown)?;
        if !rec.chain_admits_relay() {
            return Err(RelayError::NotRelayable);
        }
        if rec.is_lapsed(now) {
            return Err(RelayError::Lapsed);
        }
        if let Some(statement) = disclosure(&rec)
            && !disclosure_acknowledged
        {
            return Err(RelayError::DisclosureNotShown(statement));
        }
        let own = super::own_did(state).await.unwrap_or_default();
        let mut added = 0usize;
        for did in resolve(state, selection).await? {
            // Never to this community, the originator or any earlier relayer (VTI-NTF-047),
            // and never twice.
            if identity(&did) == identity(&own)
                || rec.excluded(&did)
                || rec
                    .relayed_to
                    .iter()
                    .any(|t| identity(&t.did) == identity(&did))
            {
                continue;
            }
            rec.relayed_to.push(RelayedTo { did, revision: 0 });
            added += 1;
        }
        rec.relay_decisions.push(RelayDecision {
            decided_at: now,
            decided_by: decided_by.to_string(),
            recipients: selection.clone(),
            recipient_count: added,
            revision: rec.revision,
            disclosure_acknowledged,
        });
        state
            .notifications_ks
            .insert(record_key(record_id), &rec)
            .await?;
        (rec, added)
    };
    audit_decision(
        state,
        decided_by,
        &rec,
        selection,
        added,
        disclosure_acknowledged,
    )
    .await;
    let revision = rec.revision;
    queue_pending(state, &mut rec, now).await?;
    Ok(RelayOutcome {
        revision,
        recipient_count: added,
    })
}

/// VTI-NTF-073: the administrator (the row's actor), the notification, the revision, the
/// selection, the count and the acknowledgement — never the parties reached.
async fn audit_decision(
    state: &AppState,
    actor: &str,
    rec: &ReceivedNotification,
    selection: &Selection,
    added: usize,
    acknowledged: bool,
) {
    use vtc_audit::{AuditEvent, NotificationRelayDecidedData};
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let (group_id, role) = match selection {
        Selection::AllMembers => (None, None),
        Selection::Group { group_id } => (Some(group_id.clone()), None),
        Selection::Role { role } => (None, Some(role.clone())),
    };
    let data = NotificationRelayDecidedData {
        record_id: rec.record_id.clone(),
        originator: rec.originator.clone(),
        notification_id: rec.notification["notificationId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        revision: rec.revision,
        scope: selection.scope().to_string(),
        group_id,
        role,
        recipient_count: u32::try_from(added).unwrap_or(u32::MAX),
        disclosure_acknowledged: acknowledged,
    };
    if let Err(e) = writer
        .write(actor, None, AuditEvent::NotificationRelayDecided(data))
        .await
    {
        tracing::warn!(error = %e, "could not audit a notification relay decision");
    }
}

/// Queue a relay of the revision held to every member it was relayed to at a lower one, then
/// record it. A crash between queueing and recording queues the same revision again, which a
/// recipient holds as the one notification it is (VTI-NTF-022). A member the revision held now
/// names as its originator or a relayer is passed over, never relayed to (VTI-NTF-047).
async fn queue_pending(
    state: &AppState,
    rec: &mut ReceivedNotification,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let deliver_by = super::deliver_by(
        Some(rec.keep_until),
        now,
        std::time::Duration::from_secs(3600),
    );
    let mut settled = Vec::new();
    let mut queued = 0usize;
    for target in rec.relayed_to.iter().filter(|t| t.revision < rec.revision) {
        if rec.excluded(&target.did) {
            settled.push(target.did.clone());
            continue;
        }
        let payload = json!({ "forwarded": rec.document });
        match super::push_signed(
            state,
            &target.did,
            TASK_NOTIFICATIONS_RELAY_0_1,
            payload,
            deliver_by,
        )
        .await
        {
            Ok(_) => {
                settled.push(target.did.clone());
                queued += 1;
            }
            Err(e) => {
                tracing::warn!(error = %e, "a relay could not be queued; the next pass tries again")
            }
        }
    }
    if settled.is_empty() {
        return Ok(0);
    }
    let _guard = WRITE_LOCK.lock().await;
    // Re-read: a later revision may have landed meanwhile, and must still be relayed.
    let Some(mut current) = get(state, &rec.record_id).await? else {
        return Ok(queued);
    };
    for t in current.relayed_to.iter_mut() {
        if settled.contains(&t.did) {
            t.revision = t.revision.max(rec.revision);
        }
    }
    state
        .notifications_ks
        .insert(record_key(&current.record_id), &current)
        .await?;
    *rec = current;
    Ok(queued)
}

/// The once-a-minute pass: relay every later revision to the members an earlier one was relayed
/// to (VTI-NTF-044), and discard records — with their relay record — past `keep_until`.
///
/// # Errors
/// A store failure listing the records; one record's failure is logged and the pass goes on.
pub async fn settle(state: &AppState, now: DateTime<Utc>) -> Result<(), AppError> {
    for mut rec in list(state).await? {
        if rec.keep_until <= now {
            let _guard = WRITE_LOCK.lock().await;
            let notification_id = rec.notification["notificationId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            state
                .notifications_ks
                .remove(record_key(&rec.record_id))
                .await?;
            state
                .notifications_ks
                .remove(dedup_key(&rec.originator, &notification_id))
                .await?;
            continue;
        }
        if rec.relayed_to.iter().any(|t| t.revision < rec.revision)
            && let Err(e) = queue_pending(state, &mut rec, now).await
        {
            tracing::warn!(error = %e, "could not relay a later revision this pass");
        }
    }
    Ok(())
}

/// Run [`settle`] every minute until shutdown.
pub fn spawn(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = settle(&state, Utc::now()).await {
                tracing::warn!(error = %e, "notification pass failed; it runs again within the minute");
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminAuthority, VtcAclEntry, VtcRole};
    use trust_tasks_rs::TrustTask;
    use vta_sdk::provision_client::EphemeralSetupKey;
    use vta_sdk::trust_task_sign::{HolderKey, sign_in_place_with};
    use vta_sdk::trust_tasks::TASK_NOTIFICATIONS_NOTIFY_0_1;

    struct Party {
        did: String,
        key: HolderKey,
    }

    fn party() -> Party {
        let k = EphemeralSetupKey::generate().unwrap();
        Party {
            key: HolderKey::from_did_key(&k.did, k.private_key_multibase()).unwrap(),
            did: k.did,
        }
    }

    async fn signed(from: &Party, to: &str, type_uri: &str, payload: Value) -> Value {
        let mut doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": from.did,
            "recipient": to,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        }))
        .unwrap();
        sign_in_place_with(&mut doc, &from.key).await.unwrap();
        serde_json::to_value(&doc).unwrap()
    }

    fn notification(
        id: &str,
        revision: u64,
        status: &str,
        relayable: bool,
        held_by: &str,
    ) -> Value {
        json!({ "notification": {
            "notificationId": id,
            "revision": revision,
            "kind": "election",
            "subject": {
                "heldBy": held_by,
                "id": "board-2027",
                "openWith": vta_sdk::notifications::ELECTION_OPEN_WITH,
            },
            "audience": held_by,
            "status": status,
            "relayable": relayable,
            "validUntil": (Utc::now() + chrono::Duration::days(7))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }})
    }

    async fn vtc(own: &Party) -> crate::test_support::TestVtc {
        crate::test_support::TestVtc::builder()
            .vtc_did(own.did.clone())
            .build()
            .await
    }

    async fn admit_acl(state: &AppState, did: &str) {
        let entry = VtcAclEntry::new(did, VtcRole::Member, AdminAuthority::none(), "test");
        crate::acl::storage::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();
    }

    async fn deliver(state: &AppState, doc: &Value) -> Disposition {
        let delivery = vta_sdk::notifications::verify_delivery(
            doc,
            &vti_common::auth::TrustTaskVmResolver::did_key_only(),
        )
        .await
        .expect("verifies");
        receive(state, &delivery, Utc::now()).await.unwrap()
    }

    /// VTI-NTF-030: the community holds a notification only from a party with standing here,
    /// and VTI-NTF-022: one record per originator and notificationId, a higher revision
    /// replacing it.
    #[tokio::test]
    async fn vti_ntf_030_the_community_holds_only_from_a_party_with_standing() {
        let own = party();
        let tv = vtc(&own).await;
        let originator = party();
        let stranger = party();
        let n = |rev, status| notification("n1", rev, status, true, &originator.did);

        let from_stranger = signed(
            &stranger,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            n(1, "available"),
        )
        .await;
        assert_eq!(
            deliver(&tv.state, &from_stranger).await,
            Disposition::Declined
        );

        admit_acl(&tv.state, &originator.did).await;
        let first = signed(
            &originator,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            n(1, "available"),
        )
        .await;
        assert!(matches!(
            deliver(&tv.state, &first).await,
            Disposition::Held { .. }
        ));
        assert_eq!(deliver(&tv.state, &first).await, Disposition::Unchanged);
        let second = signed(
            &originator,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            n(2, "withdrawn"),
        )
        .await;
        assert!(matches!(
            deliver(&tv.state, &second).await,
            Disposition::Replaced { .. }
        ));

        let held = list(&tv.state).await.unwrap();
        assert_eq!(held.len(), 1);
        assert!(held[0].withdrawn);
        assert_eq!(held[0].document, second, "kept exactly as received");
    }

    /// VTI-NTF-046 / VTI-NTF-041 / VTI-NTF-044: a relay is refused until whoever decides it has
    /// been shown what it discloses, never made of a notification that may not be relayed, and
    /// once decided records whom it goes to — every member but the party that delivered it.
    #[tokio::test]
    async fn vti_ntf_046_a_relay_is_decided_only_after_the_disclosure_is_shown() {
        let own = party();
        let tv = vtc(&own).await;
        let originator = party();
        admit_acl(&tv.state, &originator.did).await;
        let member = member(&tv.state, VtcRole::Member).await;

        let relayable = signed(
            &originator,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            notification("r1", 1, "available", true, &originator.did),
        )
        .await;
        let Disposition::Held { record_id } = deliver(&tv.state, &relayable).await else {
            panic!("held");
        };
        match relay(
            &tv.state,
            &record_id,
            "did:key:admin",
            &Selection::AllMembers,
            false,
            Utc::now(),
        )
        .await
        {
            Err(RelayError::DisclosureNotShown(statement)) => {
                assert!(statement.contains("member of the community"));
            }
            other => panic!("expected the disclosure first, got {other:?}"),
        }
        assert!(
            get(&tv.state, &record_id)
                .await
                .unwrap()
                .unwrap()
                .relayed_to
                .is_empty()
        );

        // Decided: the members are recorded before anything is queued.
        let _ = relay(
            &tv.state,
            &record_id,
            "did:key:admin",
            &Selection::AllMembers,
            true,
            Utc::now(),
        )
        .await;
        let rec = get(&tv.state, &record_id).await.unwrap().unwrap();
        assert_eq!(rec.relay_decisions.len(), 1);
        assert_eq!(rec.relay_decisions[0].decided_by, "did:key:admin");
        assert_eq!(rec.relay_decisions[0].recipient_count, 1);
        assert_eq!(
            rec.relayed_to
                .iter()
                .map(|t| t.did.as_str())
                .collect::<Vec<_>>(),
            vec![member.did.as_str()]
        );

        let fixed = signed(
            &originator,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            notification("r2", 1, "available", false, &originator.did),
        )
        .await;
        let Disposition::Held { record_id } = deliver(&tv.state, &fixed).await else {
            panic!("held");
        };
        assert!(matches!(
            relay(
                &tv.state,
                &record_id,
                "did:key:admin",
                &Selection::AllMembers,
                true,
                Utc::now()
            )
            .await,
            Err(RelayError::NotRelayable)
        ));
    }

    /// An active member: an ACL entry and a member record.
    async fn member(state: &AppState, role: VtcRole) -> Party {
        let p = party();
        let entry = VtcAclEntry::new(&p.did, role, AdminAuthority::none(), "test");
        crate::acl::storage::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();
        let m: crate::members::Member = serde_json::from_value(json!({
            "did": p.did, "joinedAt": Utc::now().to_rfc3339(),
        }))
        .unwrap();
        crate::members::storage::store_member(&state.members_ks, &m)
            .await
            .unwrap();
        p
    }

    async fn decide(state: &AppState, record_id: &str, selection: Selection) -> RelayOutcome {
        relay(
            state,
            record_id,
            "did:key:admin",
            &selection,
            true,
            Utc::now(),
        )
        .await
        .expect("relayed")
    }

    fn relayed_to(state_rec: &ReceivedNotification) -> Vec<String> {
        let mut v: Vec<String> = state_rec.relayed_to.iter().map(|t| t.did.clone()).collect();
        v.sort();
        v
    }

    /// VTI-NTF-041: the community may relay a notification that reached it through three
    /// relays — its own is the fourth — and not one that reached it through four.
    #[tokio::test]
    async fn vti_ntf_041_the_fourth_relay_is_allowed_and_a_fifth_is_not() {
        let own = party();
        let tv = vtc(&own).await;
        let originator = party();
        let hops: Vec<Party> = (0..4).map(|_| party()).collect();

        // originator → hop0 → hop1 → hop2 → (hop3 →) community
        async fn chain(originator: &Party, hops: &[Party], to: &str, id: &str) -> Value {
            let mut layer = signed(
                originator,
                &hops[0].did,
                TASK_NOTIFICATIONS_NOTIFY_0_1,
                notification(id, 1, "available", true, &originator.did),
            )
            .await;
            for w in hops.windows(2) {
                layer = signed(
                    &w[0],
                    &w[1].did,
                    TASK_NOTIFICATIONS_RELAY_0_1,
                    json!({ "forwarded": layer }),
                )
                .await;
            }
            signed(
                hops.last().unwrap(),
                to,
                TASK_NOTIFICATIONS_RELAY_0_1,
                json!({ "forwarded": layer }),
            )
            .await
        }

        admit_acl(&tv.state, &hops[2].did).await;
        let three = chain(&originator, &hops[..3], &own.did, "three").await;
        let Disposition::Held { record_id } = deliver(&tv.state, &three).await else {
            panic!("held");
        };
        let rec = get(&tv.state, &record_id).await.unwrap().unwrap();
        assert_eq!(rec.relayed_by.len(), 3);
        assert!(rec.may_relay(Utc::now()));
        decide(&tv.state, &record_id, Selection::AllMembers).await;

        admit_acl(&tv.state, &hops[3].did).await;
        let four = chain(&originator, &hops, &own.did, "four").await;
        let Disposition::Held { record_id } = deliver(&tv.state, &four).await else {
            panic!("held");
        };
        let rec = get(&tv.state, &record_id).await.unwrap().unwrap();
        assert!(!rec.may_relay(Utc::now()));
        assert!(matches!(
            relay(
                &tv.state,
                &record_id,
                "did:key:admin",
                &Selection::AllMembers,
                true,
                Utc::now()
            )
            .await,
            Err(RelayError::NotRelayable)
        ));
    }

    /// VTI-NTF-047: never to the originator, to any relayer the received chain names, or to the
    /// community itself — even where each is an active member — and VTI-NTF-072: a repeat of a
    /// decision adds nobody.
    #[tokio::test]
    async fn vti_ntf_047_never_back_to_the_originator_or_an_earlier_relayer() {
        let own = party();
        let tv = vtc(&own).await;
        let originator = member(&tv.state, VtcRole::Member).await;
        let relayer = member(&tv.state, VtcRole::Member).await;
        let other = member(&tv.state, VtcRole::Member).await;
        let inner = signed(
            &originator,
            &relayer.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            notification("loop", 1, "available", true, &originator.did),
        )
        .await;
        let delivered = signed(
            &relayer,
            &own.did,
            TASK_NOTIFICATIONS_RELAY_0_1,
            json!({ "forwarded": inner }),
        )
        .await;
        let Disposition::Held { record_id } = deliver(&tv.state, &delivered).await else {
            panic!("held");
        };
        let first = decide(&tv.state, &record_id, Selection::AllMembers).await;
        assert_eq!(first.recipient_count, 1);
        let rec = get(&tv.state, &record_id).await.unwrap().unwrap();
        assert_eq!(relayed_to(&rec), vec![other.did.clone()]);
        let again = decide(&tv.state, &record_id, Selection::AllMembers).await;
        assert_eq!(again.recipient_count, 0);
    }

    /// VTI-NTF-072: a selection names one group's or one role's active members, resolved at
    /// the decision; a member who joins the set later is not added without a new decision.
    #[tokio::test]
    async fn vti_ntf_072_a_selection_is_resolved_once_from_the_communitys_records() {
        let own = party();
        let tv = vtc(&own).await;
        let originator = party();
        admit_acl(&tv.state, &originator.did).await;
        let moderator = member(&tv.state, VtcRole::Moderator).await;
        let _plain = member(&tv.state, VtcRole::Member).await;
        let doc = signed(
            &originator,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            notification("sel", 1, "available", true, &originator.did),
        )
        .await;
        let Disposition::Held { record_id } = deliver(&tv.state, &doc).await else {
            panic!("held");
        };
        let out = decide(
            &tv.state,
            &record_id,
            Selection::Role {
                role: "moderator".into(),
            },
        )
        .await;
        assert_eq!(out.recipient_count, 1);
        let rec = get(&tv.state, &record_id).await.unwrap().unwrap();
        assert_eq!(relayed_to(&rec), vec![moderator.did.clone()]);

        // Joins the role afterwards: not reached until someone decides again.
        let _late = member(&tv.state, VtcRole::Moderator).await;
        let rec = get(&tv.state, &record_id).await.unwrap().unwrap();
        assert_eq!(rec.relayed_to.len(), 1);

        assert!(matches!(
            relay(
                &tv.state,
                &record_id,
                "did:key:admin",
                &Selection::Group {
                    group_id: "grp_none".into()
                },
                true,
                Utc::now()
            )
            .await,
            Err(RelayError::GroupUnknown)
        ));
    }

    /// VTI-NTF-034: a network the community is itself a member of, by its own acknowledged
    /// record, is a party the policy counts; a listing it never acknowledged is not.
    #[tokio::test]
    async fn vti_ntf_034_an_acknowledged_network_membership_counts_and_a_listing_does_not() {
        let own = party();
        let tv = vtc(&own).await;
        let network = party();
        let listed_only = party();
        for (did, acknowledged) in [(&network.did, true), (&listed_only.did, false)] {
            let m: crate::networks::Membership = serde_json::from_value(json!({
                "network": did,
                "url": "https://network.example",
                "state": if acknowledged { "acknowledged" } else { "repudiated" },
                "listing": {},
                "updatedAt": Utc::now().to_rfc3339(),
            }))
            .unwrap();
            tv.state
                .community_ks
                .insert(format!("network-membership:{did}"), &m)
                .await
                .unwrap();
        }
        let from_network = signed(
            &network,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            notification("vtn", 1, "available", true, &network.did),
        )
        .await;
        assert!(matches!(
            deliver(&tv.state, &from_network).await,
            Disposition::Held { .. }
        ));
        let from_listing = signed(
            &listed_only,
            &own.did,
            TASK_NOTIFICATIONS_NOTIFY_0_1,
            notification("vtn2", 1, "available", true, &listed_only.did),
        )
        .await;
        assert_eq!(
            deliver(&tv.state, &from_listing).await,
            Disposition::Declined
        );
    }
}
