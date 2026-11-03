//! Notifications addressed to this community, and relaying them to its members
//! (VTI-NTF-022 – 033, VTI-NTF-040 – 046).
//!
//! # The stated acceptance policy (VTI-NTF-030)
//!
//! A verified notification is held when the party that delivered it — the originator, or for a
//! relay the last relayer (VTI-NTF-031) — holds an ACL entry at this community, or is a party
//! to a relationship credential in force with the community's own DID. Everything else is
//! declined, and answered with the same receipt (VTI-NTF-023).
//!
//! # Relaying
//!
//! Nothing is relayed by itself. An administrator decides a relay ([`relay_to_members`]) and is
//! shown first what it discloses ([`vta_sdk::notifications::relay_disclosure`], VTI-NTF-046): a
//! decision that has not acknowledged the disclosure is refused. A relay carries the document
//! this community received **exactly as received** (VTI-NTF-041), one `notifications/relay/0.1`
//! per member, queued on the durable member push. The record of whom it was relayed to is kept
//! until the notification's period ends — or, with no period, for [`RELAY_RECORD_DAYS`] — and
//! used for nothing but relaying later revisions to the same members, a withdrawal included
//! (VTI-NTF-044): [`settle`] does that, once a minute, and is the one retry owner.
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
    /// Who decided to relay it, and when; `None` until an administrator does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_decided_at: Option<DateTime<Utc>>,
    /// Whom it was relayed to (VTI-NTF-044). Used for nothing else.
    #[serde(default)]
    pub relayed_to: Vec<RelayedTo>,
    /// When the record, and with it the relay record, is discarded.
    pub keep_until: DateTime<Utc>,
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

/// Every notification held, most recently received first.
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
    out.sort_by(|a, b| b.received_at.cmp(&a.received_at));
    Ok(out)
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

/// The stated policy: whether `party` stands in a relationship with this community.
async fn has_standing(state: &AppState, party: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
    let party = identity(party);
    if let Some(entry) = crate::acl::storage::get_acl_entry(&state.acl_ks, &party).await? {
        let _ = entry;
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
        relay_decided_by: None,
        relay_decided_at: None,
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
    /// No such held notification.
    Unknown,
    /// Its originator says it may not be relayed, or it already carries the most relays this
    /// community may add to (VTI-NTF-041, VTI-NTF-042).
    NotRelayable,
    /// It has lapsed or been withdrawn: there is nothing to tell members of.
    Lapsed,
    /// The decision did not acknowledge what the relay discloses (VTI-NTF-046). Carries the
    /// statement to show.
    DisclosureNotShown(&'static str),
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

/// An administrator's decision to relay `record_id` to every active member. Records the
/// decision and the members, then queues one relay each; returns how many were queued.
/// `disclosure_acknowledged` is the decider's statement that they were shown [`disclosure`].
///
/// # Errors
/// See [`RelayError`].
pub async fn relay_to_members(
    state: &AppState,
    record_id: &str,
    decided_by: &str,
    disclosure_acknowledged: bool,
    now: DateTime<Utc>,
) -> Result<usize, RelayError> {
    let mut rec = {
        let _guard = WRITE_LOCK.lock().await;
        let mut rec = get(state, record_id).await?.ok_or(RelayError::Unknown)?;
        // A relay may carry at most MAX_RELAYS in all; one already carrying three may not be
        // relayed again (notifications/relay producer item 2).
        if !rec.relayable
            || !vta_sdk::notifications::kind_may_be_relayed(&rec.kind)
            || rec.relayed_by.len() >= MAX_RELAYS - 1
        {
            return Err(RelayError::NotRelayable);
        }
        if rec.withdrawn || rec.valid_until.is_some_and(|u| u <= now) {
            return Err(RelayError::Lapsed);
        }
        if let Some(statement) = disclosure(&rec)
            && !disclosure_acknowledged
        {
            return Err(RelayError::DisclosureNotShown(statement));
        }
        let own = super::own_did(state).await.unwrap_or_default();
        let members = crate::members::storage::list_members(&state.members_ks).await?;
        for m in members {
            // Never back to whoever passed it here, nor to this community itself.
            let did = identity(&m.did);
            if did == identity(&own)
                || did == identity(&rec.delivered_by)
                || rec.relayed_to.iter().any(|t| identity(&t.did) == did)
            {
                continue;
            }
            rec.relayed_to.push(RelayedTo {
                did: m.did,
                revision: 0,
            });
        }
        rec.relay_decided_by = Some(decided_by.to_string());
        rec.relay_decided_at = Some(now);
        state
            .notifications_ks
            .insert(record_key(record_id), &rec)
            .await?;
        rec
    };
    Ok(queue_pending(state, &mut rec, now).await?)
}

/// Queue a relay of the revision held to every member it was relayed to at a lower one, then
/// record it. A crash between queueing and recording queues the same revision again, which a
/// recipient holds as the one notification it is (VTI-NTF-022).
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
    let mut queued = Vec::new();
    for target in rec.relayed_to.iter().filter(|t| t.revision < rec.revision) {
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
            Ok(_) => queued.push(target.did.clone()),
            Err(e) => {
                tracing::warn!(error = %e, "a relay could not be queued; the next pass tries again")
            }
        }
    }
    if queued.is_empty() {
        return Ok(0);
    }
    let _guard = WRITE_LOCK.lock().await;
    // Re-read: a later revision may have landed meanwhile, and must still be relayed.
    let Some(mut current) = get(state, &rec.record_id).await? else {
        return Ok(queued.len());
    };
    for t in current.relayed_to.iter_mut() {
        if queued.contains(&t.did) {
            t.revision = t.revision.max(rec.revision);
        }
    }
    state
        .notifications_ks
        .insert(record_key(&current.record_id), &current)
        .await?;
    *rec = current;
    Ok(queued.len())
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
