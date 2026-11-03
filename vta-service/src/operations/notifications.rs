//! The notifications this VTA holds for its principal (VTI-NTF-022 – 033, VTI-NTF-050 – 053).
//!
//! A `notifications/notify` or `notifications/relay` document reaches this VTA over TSP or
//! DIDComm from a party that usually holds no ACL entry here — a community, a group, a network.
//! The dispatch spine has bound the document to its sender and applied the acceptance window;
//! the handler verifies every layer ([`vta_sdk::notifications::verify_delivery`]) and passes the
//! [`VerifiedDelivery`] to [`receive`], which decides by the stated acceptance policy
//! (`[notifications]`, VTI-NTF-030) whether to hold it, and holds it in the trust context of the
//! DID it was addressed to (VTI-NTF-050).
//!
//! # Invariants
//!
//! - **One record per (addressee, originator, `notificationId`)** (VTI-NTF-022), originators
//!   compared as identities (VTI-KEY-160 – 169). A higher revision replaces the record and keeps
//!   its `recordId` and its dismissal; an equal or lower one changes nothing.
//! - **The receipt says nothing** (VTI-NTF-023): [`receive`] returns `()` whatever it did, so the
//!   handler cannot answer differently for held, declined or discarded.
//! - **A relayed notification is accepted on the relayer's standing** (VTI-NTF-031):
//!   [`VerifiedDelivery::delivered_by`], never the originator.
//! - **Bounded** (VTI-NTF-033): at most [`MAX_PER_ORIGINATOR`] held notifications from one
//!   originator and [`MAX_PER_DELIVERER`] delivered by one party; a new one past either is
//!   declined (a revision of one already held is always taken).
//! - **Holding tells nobody anything** (VTI-NTF-053): nothing here sends a message.
//! - **Contexts are walls** (VTI-NTF-051): every read and the dismissal look a record up under
//!   the caller's named context only, and an unknown record and one in another context answer
//!   alike.
//!
//! # Storage
//!
//! [`crate::keyspaces::NOTIFICATIONS`]: `held:<ctx>\0<recordId>` → [`HeldRecord`];
//! `dedup:<digest>` → `<ctx>\0<recordId>`; `orig:<digest>:<ctx>\0<recordId>` and
//! `dlv:<digest>:<ctx>\0<recordId>` count the bounds. Written in one batch.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vta_sdk::notifications::{VerifiedDelivery, identity};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

use crate::auth::AuthClaims;
use crate::server::AppState;

/// The most notifications held from any one originator (VTI-NTF-033).
pub const MAX_PER_ORIGINATOR: usize = 256;
/// The most notifications held that any one party delivered (VTI-NTF-033).
pub const MAX_PER_DELIVERER: usize = 1024;
/// The largest page `list` returns.
pub const LIST_MAX_PAGE: usize = 200;
/// The page `list` returns when the caller names no `limit`.
pub const LIST_DEFAULT_PAGE: usize = 50;

/// Serialises every write to the keyspace: dedup-then-write must be one critical section, or
/// two copies of one notification arriving together (by two relayers) would make two records.
static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The principal's disposition of a held notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HeldState {
    Active,
    Dismissed,
}

/// One held notification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldRecord {
    pub record_id: String,
    pub context_id: String,
    pub addressee: String,
    pub originator: String,
    pub relayed_by: Vec<String>,
    /// The party whose standing the acceptance policy counted (VTI-NTF-031).
    pub delivered_by: String,
    /// The notification's members exactly as the originator signed them.
    pub notification: Value,
    pub revision: u64,
    pub kind: String,
    pub held_by: String,
    pub withdrawn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub state: HeldState,
    pub received_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissed_at: Option<DateTime<Utc>>,
    /// When the record lapsed — withdrawn, or its `validUntil` — and so when the retention
    /// period before discarding it starts (VTI-NTF-052).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lapsed_at: Option<DateTime<Utc>>,
    /// The delivering document, exactly as received.
    pub document: Value,
}

impl HeldRecord {
    /// Whether the thing can no longer be acted on: withdrawn, or past its `validUntil`.
    #[must_use]
    pub fn is_lapsed(&self, now: DateTime<Utc>) -> bool {
        self.withdrawn || self.valid_until.is_some_and(|until| until <= now)
    }

    /// The record as `HeldNotification` (`vta/notifications/_shared/0.1`).
    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut v = serde_json::json!({
            "recordId": self.record_id,
            "contextId": self.context_id,
            "addressee": self.addressee,
            "originator": self.originator,
            "relayedBy": self.relayed_by,
            "notification": self.notification,
            "state": match self.state { HeldState::Active => "active", HeldState::Dismissed => "dismissed" },
            "receivedAt": self.received_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        if let Some(at) = self.dismissed_at {
            v["dismissedAt"] = Value::String(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
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

fn held_key(ctx: &str, record_id: &str) -> String {
    format!("held:{ctx}\0{record_id}")
}

fn dedup_key(addressee: &str, originator: &str, notification_id: &str) -> String {
    format!(
        "dedup:{}",
        digest(&[&identity(addressee), &identity(originator), notification_id])
    )
}

fn originator_prefix(originator: &str) -> String {
    format!("orig:{}:", digest(&[&identity(originator)]))
}

fn deliverer_prefix(deliverer: &str) -> String {
    format!("dlv:{}:", digest(&[&identity(deliverer)]))
}

/// The trust context the DID `did` belongs to, when this VTA holds its keys (VTI-NTF-050): a
/// `did:webvh` (or its `did:scid`) this VTA minted, by its record; a `did:key` or `did:peer`,
/// by the context of the key record its method names. `None` for a DID this VTA does not hold.
pub async fn held_context_of(state: &AppState, did: &str) -> Result<Option<String>, AppError> {
    let did = identity(did);
    #[cfg(feature = "webvh")]
    {
        let log_did = if vta_sdk::did_scid::is_scid(&did) {
            crate::webvh_store::log_did_for(&state.webvh_ks, &did).await?
        } else {
            Some(did.clone())
        };
        if let Some(log_did) = log_did
            && let Some(record) = crate::webvh_store::get_did(&state.webvh_ks, &log_did).await?
        {
            return Ok(Some(record.context_id));
        }
    }
    if did.starts_with("did:key:") || did.starts_with("did:peer:") {
        // Read with the VTA's own, unrestricted standing: the question is where the DID is
        // held, not whether some caller may act as it.
        let own = AuthClaims {
            did: String::new(),
            role: crate::acl::Role::Admin,
            allowed_contexts: Vec::new(),
            ..Default::default()
        };
        let stores = crate::operations::persona::PersonaStores::from_state(state);
        let Some(key) = crate::operations::persona::persona_key_for(
            stores,
            &own,
            &did,
            crate::operations::persona::Relationship::AssertionMethod,
        )
        .await?
        else {
            return Ok(None);
        };
        let record: Option<vta_sdk::keys::KeyRecord> =
            state.keys_ks.get(vta_keys::store_key(&key.key_id)).await?;
        return Ok(record.and_then(|r| r.context_id));
    }
    Ok(None)
}

/// Why the acceptance policy held a notification (logged, never answered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    AclEntry,
    MembershipCredential,
    RelationshipCredential,
    PrincipalChose,
}

/// The stated acceptance policy (VTI-NTF-030): whether the principal holds a relationship
/// with `party`, counted in `context`.
pub async fn standing_of(
    state: &AppState,
    party: &str,
    context: &str,
) -> Result<Option<Standing>, AppError> {
    let party = identity(party);
    {
        let config = state.config.read().await;
        if config.notifications.accept_any
            || config
                .notifications
                .accept_from
                .iter()
                .any(|d| identity(d) == party)
        {
            return Ok(Some(Standing::PrincipalChose));
        }
    }
    if let Some(entry) = vti_common::acl::get_acl_entry(&state.acl_ks, &party).await? {
        let live = entry
            .expires_at
            .is_none_or(|at| at > u64::try_from(Utc::now().timestamp()).unwrap_or(0));
        if live {
            return Ok(Some(Standing::AclEntry));
        }
    }
    use crate::vault::model::{CredentialPurpose, CredentialStatus, IndexField};
    let usable = |c: &crate::vault::model::StoredCredential| {
        c.is_active()
            && !matches!(
                c.status,
                CredentialStatus::Revoked | CredentialStatus::Expired
            )
            && c.context_id.as_deref().is_none_or(|ctx| ctx == context)
    };
    let is_relationship = |c: &crate::vault::model::StoredCredential| {
        c.types
            .iter()
            .any(|t| t.ends_with("RelationshipCredential"))
    };
    let is_membership = |c: &crate::vault::model::StoredCredential| {
        c.purpose == Some(CredentialPurpose::Membership)
            || c.types.iter().any(|t| t.ends_with("MembershipCredential"))
    };
    // A credential `party` issued to the principal: a membership credential (a community, a
    // group or a network the principal belongs to), or one side of a relationship credential.
    for c in
        crate::vault::storage::find_by_index(&state.vault_ks, IndexField::IssuerDid, &party).await?
    {
        if !usable(&c) {
            continue;
        }
        if is_membership(&c) {
            return Ok(Some(Standing::MembershipCredential));
        }
        if is_relationship(&c) {
            return Ok(Some(Standing::RelationshipCredential));
        }
    }
    // The other side: a relationship credential naming `party` as its subject.
    for c in crate::vault::storage::find_by_index(
        &state.vault_ks,
        IndexField::Type,
        "RelationshipCredential",
    )
    .await?
    {
        if usable(&c) && c.subject_did.as_deref().map(identity).as_deref() == Some(party.as_str()) {
            return Ok(Some(Standing::RelationshipCredential));
        }
    }
    Ok(None)
}

/// What [`receive`] did — for logs and tests only. The handler answers the same receipt
/// whatever this says (VTI-NTF-023), and must never branch on it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// A new record.
    Held { record_id: String },
    /// A higher revision replaced the record.
    Replaced { record_id: String },
    /// The same or a lower revision of a record already held.
    Unchanged,
    /// Discarded: its period has ended (VTI-NTF-032).
    Lapsed,
    /// Not addressed to a DID this VTA holds keys of.
    NotHeldHere,
    /// The acceptance policy found no relationship with the party that delivered it.
    Declined,
    /// A bound of VTI-NTF-033 is reached.
    OverBound,
}

/// Hold `delivery` if the acceptance policy accepts it. See the module docs.
pub async fn receive(
    state: &AppState,
    delivery: &VerifiedDelivery,
    now: DateTime<Utc>,
) -> Result<Disposition, AppError> {
    let n = delivery.notification();
    let valid_until = n.valid_until;
    // VTI-NTF-032: a notification whose period has ended is discarded, never held.
    if valid_until.is_some_and(|until| until <= now) {
        return Ok(Disposition::Lapsed);
    }
    let Some(context) = held_context_of(state, delivery.addressee()).await? else {
        return Ok(Disposition::NotHeldHere);
    };
    let Some(standing) = standing_of(state, delivery.delivered_by(), &context).await? else {
        tracing::debug!(
            deliverer = %delivery.delivered_by(),
            "notification declined: no relationship with the party that delivered it"
        );
        return Ok(Disposition::Declined);
    };
    tracing::debug!(?standing, "notification accepted by the stated policy");

    let ks = &state.notifications_ks;
    let revision = n.revision.get();
    let notification_id: &str = &n.notification_id;
    let dkey = dedup_key(delivery.addressee(), delivery.originator(), notification_id);
    let withdrawn = matches!(
        n.status,
        vti_specs::notifications::notify::v0_1::Status::Withdrawn
    );
    let lapsed_at = if withdrawn { Some(now) } else { valid_until };

    let _guard = WRITE_LOCK.lock().await;
    if let Some(location) = ks.get::<String>(dkey.clone()).await? {
        let Some((ctx, record_id)) = location.split_once('\0') else {
            return Err(AppError::Internal(
                "a notification index row is malformed".into(),
            ));
        };
        let Some(mut rec) = ks.get::<HeldRecord>(held_key(ctx, record_id)).await? else {
            return Err(AppError::Internal(
                "a notification index row names no record".into(),
            ));
        };
        if revision <= rec.revision {
            return Ok(Disposition::Unchanged);
        }
        let old_deliverer = rec.delivered_by.clone();
        rec.relayed_by = delivery.relayed_by().to_vec();
        rec.delivered_by = delivery.delivered_by().to_string();
        rec.notification = delivery.notification_json().clone();
        rec.revision = revision;
        rec.kind = n.kind.to_string();
        rec.held_by = n.subject.held_by.to_string();
        rec.withdrawn = withdrawn;
        rec.valid_until = valid_until;
        rec.lapsed_at = lapsed_at;
        rec.received_at = now;
        rec.document = delivery.document().clone();
        // The dismissal stays: a later revision of a dismissed notification leaves it
        // dismissed (`vta/notifications/dismiss/0.1`).
        let mut batch = Batch::new();
        let location = format!("{ctx}\0{record_id}");
        if identity(&old_deliverer) != identity(&rec.delivered_by) {
            batch.remove(format!("{}{location}", deliverer_prefix(&old_deliverer)));
            batch.insert_raw(
                format!("{}{location}", deliverer_prefix(&rec.delivered_by)),
                b"".to_vec(),
            );
        }
        batch.insert(held_key(ctx, record_id), &rec)?;
        ks.apply_batch(batch).await?;
        return Ok(Disposition::Replaced {
            record_id: record_id.to_string(),
        });
    }

    // A new notification: within the bounds (VTI-NTF-033).
    if ks
        .prefix_keys(originator_prefix(delivery.originator()))
        .await?
        .len()
        >= MAX_PER_ORIGINATOR
        || ks
            .prefix_keys(deliverer_prefix(delivery.delivered_by()))
            .await?
            .len()
            >= MAX_PER_DELIVERER
    {
        return Ok(Disposition::OverBound);
    }
    let record_id = format!("hn-{}", uuid::Uuid::new_v4().simple());
    let rec = HeldRecord {
        record_id: record_id.clone(),
        context_id: context.clone(),
        addressee: delivery.addressee().to_string(),
        originator: delivery.originator().to_string(),
        relayed_by: delivery.relayed_by().to_vec(),
        delivered_by: delivery.delivered_by().to_string(),
        notification: delivery.notification_json().clone(),
        revision,
        kind: n.kind.to_string(),
        held_by: n.subject.held_by.to_string(),
        withdrawn,
        valid_until,
        state: HeldState::Active,
        received_at: now,
        dismissed_at: None,
        lapsed_at,
        document: delivery.document().clone(),
    };
    let location = format!("{context}\0{record_id}");
    let mut batch = Batch::new();
    batch.require_absent(dkey.clone());
    batch.insert(held_key(&context, &record_id), &rec)?;
    batch.insert(dkey, &location)?;
    batch
        .insert_raw(
            format!("{}{location}", originator_prefix(delivery.originator())),
            b"".to_vec(),
        )
        .insert_raw(
            format!("{}{location}", deliverer_prefix(delivery.delivered_by())),
            b"".to_vec(),
        );
    if !ks.apply_batch(batch).await?.is_applied() {
        // Only this module writes the keyspace, under the lock.
        return Err(AppError::Conflict(
            "a notification was recorded concurrently".into(),
        ));
    }
    Ok(Disposition::Held { record_id })
}

/// The filters of `vta/notifications/list/0.1`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    pub kind: Option<String>,
    pub held_by: Option<String>,
    pub include_dismissed: bool,
    pub include_lapsed: bool,
}

impl ListFilter {
    fn digest(&self, context: &str) -> String {
        digest(&[
            context,
            self.kind.as_deref().unwrap_or(""),
            self.held_by.as_deref().unwrap_or(""),
            if self.include_dismissed { "d" } else { "" },
            if self.include_lapsed { "l" } else { "" },
        ])[..16]
            .to_string()
    }

    fn admits(&self, rec: &HeldRecord, now: DateTime<Utc>) -> bool {
        self.kind.as_deref().is_none_or(|k| rec.kind == k)
            && self
                .held_by
                .as_deref()
                .is_none_or(|h| identity(h) == identity(&rec.held_by))
            && (self.include_dismissed || rec.state == HeldState::Active)
            && (self.include_lapsed || !rec.is_lapsed(now))
    }
}

/// A refusal of a list, show or dismiss.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
    /// The caller has no standing in the context (VTI-NTF-051).
    PermissionDenied,
    /// No record under that identifier in that context.
    Unknown,
    /// A cursor this VTA did not issue for these filters.
    CursorInvalid,
    App(AppError),
}

impl From<AppError> for ReadError {
    fn from(e: AppError) -> Self {
        ReadError::App(e)
    }
}

/// One page of a list.
#[derive(Debug)]
pub struct Page {
    pub items: Vec<HeldRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    f: String,
    t: DateTime<Utc>,
    r: String,
}

fn records_in(rows: Vec<(Vec<u8>, Vec<u8>)>) -> impl Iterator<Item = HeldRecord> {
    rows.into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<HeldRecord>(&v).ok())
}

/// `vta/notifications/list/0.1`: the held notifications of `context` the filter admits, most
/// recently received first.
pub async fn list(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    filter: &ListFilter,
    cursor: Option<&str>,
    limit: Option<usize>,
    now: DateTime<Utc>,
) -> Result<Page, ReadError> {
    if !auth.has_context_access(context) {
        return Err(ReadError::PermissionDenied);
    }
    let fdigest = filter.digest(context);
    let after = match cursor {
        None => None,
        Some(c) => {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .map_err(|_| ReadError::CursorInvalid)?;
            let cur: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| ReadError::CursorInvalid)?;
            if cur.f != fdigest {
                return Err(ReadError::CursorInvalid);
            }
            Some((cur.t, cur.r))
        }
    };
    let limit = limit.unwrap_or(LIST_DEFAULT_PAGE).clamp(1, LIST_MAX_PAGE);
    let rows = state
        .notifications_ks
        .prefix_iter_raw(format!("held:{context}\0"))
        .await?;
    let mut items: Vec<HeldRecord> = records_in(rows)
        .filter(|r| r.context_id == context && filter.admits(r, now))
        .collect();
    // Most recently received first; the record id breaks a tie so paging is total.
    items.sort_by(|a, b| {
        b.received_at
            .cmp(&a.received_at)
            .then_with(|| b.record_id.cmp(&a.record_id))
    });
    if let Some((t, r)) = after {
        items.retain(|x| (x.received_at, x.record_id.as_str()) < (t, r.as_str()));
    }
    let more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = if more {
        items.last().map(|last| {
            use base64::Engine;
            let cur = Cursor {
                f: fdigest.clone(),
                t: last.received_at,
                r: last.record_id.clone(),
            };
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&cur).unwrap_or_default())
        })
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

/// `vta/notifications/show/0.1`: one held record of `context`.
pub async fn show(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    record_id: &str,
) -> Result<HeldRecord, ReadError> {
    if !auth.has_context_access(context) {
        return Err(ReadError::PermissionDenied);
    }
    state
        .notifications_ks
        .get::<HeldRecord>(held_key(context, record_id))
        .await?
        .ok_or(ReadError::Unknown)
}

/// `vta/notifications/dismiss/0.1`: dismiss one held record of `context`. `Ok(true)` when this
/// request dismissed it, `Ok(false)` when it already was.
pub async fn dismiss(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    record_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, ReadError> {
    if !auth.has_context_access(context) {
        return Err(ReadError::PermissionDenied);
    }
    let _guard = WRITE_LOCK.lock().await;
    let key = held_key(context, record_id);
    let mut rec = state
        .notifications_ks
        .get::<HeldRecord>(key.clone())
        .await?
        .ok_or(ReadError::Unknown)?;
    if rec.state == HeldState::Dismissed {
        return Ok(false);
    }
    rec.state = HeldState::Dismissed;
    rec.dismissed_at = Some(now);
    state.notifications_ks.insert(key, &rec).await?;
    Ok(true)
}

/// Discard every record that lapsed more than `retain_days` ago (VTI-NTF-052), with its index
/// rows. Returns how many were discarded.
pub async fn sweep_lapsed(
    ks: &KeyspaceHandle,
    retain_days: u32,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let horizon = now - chrono::Duration::days(i64::from(retain_days));
    let _guard = WRITE_LOCK.lock().await;
    let mut removed = 0;
    for rec in records_in(ks.prefix_iter_raw("held:").await?) {
        let lapsed = rec.lapsed_at.or(rec.valid_until);
        if !lapsed.is_some_and(|at| at <= horizon) {
            continue;
        }
        discard(ks, &rec).await?;
        removed += 1;
    }
    Ok(removed)
}

/// Discard every notification held in `context`, with its index rows,
/// returning how many went.
///
/// For a context deletion. The records are keyed by context, so left behind
/// they would be listed by a context created again under the same id — and
/// their dedup and bound rows would keep counting against originators and
/// deliverers for records nobody can reach.
pub async fn purge_context(ks: &KeyspaceHandle, context: &str) -> Result<usize, AppError> {
    let _guard = WRITE_LOCK.lock().await;
    let mut removed = 0;
    for rec in records_in(ks.prefix_iter_raw(format!("held:{context}\0")).await?) {
        discard(ks, &rec).await?;
        removed += 1;
    }
    Ok(removed)
}

/// Remove one record and its dedup and bound rows, as one batch. Call under
/// [`WRITE_LOCK`].
async fn discard(ks: &KeyspaceHandle, rec: &HeldRecord) -> Result<(), AppError> {
    let location = format!("{}\0{}", rec.context_id, rec.record_id);
    let notification_id = rec.notification["notificationId"]
        .as_str()
        .unwrap_or_default();
    let mut batch = Batch::new();
    batch
        .remove(held_key(&rec.context_id, &rec.record_id))
        .remove(dedup_key(&rec.addressee, &rec.originator, notification_id))
        .remove(format!("{}{location}", originator_prefix(&rec.originator)))
        .remove(format!("{}{location}", deliverer_prefix(&rec.delivered_by)));
    ks.apply_batch(batch).await?;
    Ok(())
}
