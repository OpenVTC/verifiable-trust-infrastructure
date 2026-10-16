//! Renewing the community's own standing in the rooms it owns, before it lapses.
//!
//! When the community creates a room ([`super::community`]), its VTA issues it a
//! membership and an `admin` authority credential in the room's name, both valid
//! `[rooms.community] authority_valid_days`, and keeps them in its vault: they are what it
//! presents when it advances the room for an admission or a removal. A room whose owner's
//! authority has lapsed can no longer advance its epoch, admit or remove
//! (`vtc/_shared/0.1/community-room`, `ownerAuthorityValidUntil`), and
//! `vtc/rooms/community/create` item 6 says a community **SHOULD** renew it well before.
//! This is that renewal: no new task, only the ones the VTA already serves for every owner.
//!
//! # What a renewal is
//!
//! For a room whose authority expires within `[rooms.community]
//! authority_renew_within_days` (default 30, never more than half the authority's life),
//! the community asks its VTA for a fresh membership (`rooms/owner/issue-membership`) and
//! a fresh `admin` authority (`rooms/owner/issue-authority`, the same four actions), each
//! valid `authority_valid_days` from now, and stores each in the VTA's vault
//! (`vault/credentials/receive`) **under the handle the one it replaces is stored under**.
//! The membership is renewed with the authority because the room issued both with the same
//! expiry; renewing one would leave the other to lapse on the old date.
//!
//! Replacing by handle, never adding beside, is load-bearing: the VTA refuses to act for a
//! persona holding two authority credentials from one room rather than guess between them,
//! so a second copy would stop every admission and removal until somebody deleted one.
//! `receive` with an `id` is a write under the caller's own naming (its *Definitions*), so
//! the store at the VTA is a single replacement. The handles come from the create, which
//! records what `receive` answered; for a room created before that, from the VTA's own
//! vault (`vault/credentials/query` by issuer and type, then `get` to keep the one whose
//! subject is this community), which takes `vault-read` on the community's entry there.
//!
//! # Remote first, and crash-safe
//!
//! Nothing here is committed before the VTA holds the new credentials. The one local write
//! — the new `ownerAuthorityValidUntil` on the owner's record — comes last. A process that
//! dies anywhere before it finds the room still due on its next pass and renews again,
//! storing under the same handles: the VTA ends with one membership and one authority
//! either way, the newer replacing the older. The handles and the retry schedule live in
//! this module's own record (`authority-renewal:<room>`), beside the owner's record in the
//! `community_rooms` keyspace and never inside it.
//!
//! # One retry owner
//!
//! The sweeper is the only thing that retries a renewal. Each pass makes at most one
//! attempt per due room, one request per step; a failure is recorded with the next time to
//! try, a capped exponential backoff with jitter (1 minute doubling to 6 hours). Nothing
//! is retried inside an attempt.
//!
//! # Failures are seen
//!
//! A failure is logged at `warn` every time, audited (`CommunityRoomChanged`,
//! `authorityRenewalFailed`) when a run of failures begins, and shown to the console in
//! `vtc/rooms/community/{get,list}`'s `ext["org.openvtc"].authorityRenewal` (the shared
//! `CommunityRoom` definition has no member for it). A renewal is audited
//! `authorityRenewed`, and the owner's record write hints the console's `rooms` topic.
//!
//! # What is never renewed
//!
//! Nothing while community rooms are off, while there is no VTA link, or while the
//! community has no DID. A room this service no longer hosts, one whose owner is no longer
//! this community, and one past its retention (`reclaimable`) are left alone. A room whose
//! authority has already lapsed is still renewed: the room's key, held by the VTA, is what
//! issues, and that is how such a room is recovered.
//!
//! There is no "renew now" task: no specification defines one, and a community's
//! administrator can already reissue by hand at its VTA (`pnm rooms owner issue-authority`).

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::rooms::owner::{
    issue_authority::v0_2 as owner_authority, issue_membership::v0_1 as owner_membership,
};
use trust_tasks_rs::specs::vault::credentials::{
    get::v0_1 as vault_get, query::v0_1 as vault_query, receive::v0_1 as vault_receive,
};
use vti_common::audit::{AuditEvent, CommunityRoomChangedData};
use vti_common::error::AppError;

use super::community::{CommunityRooms, HolderError, KeyHolder, OwnedRoom, SIGN_TIMEOUT};
use crate::config::CommunityRoomsConfig;
use crate::server::AppState;

/// `[rooms.community] authority_renew_within_days`, when absent.
pub const DEFAULT_RENEW_WITHIN_DAYS: u32 = 30;

/// How often the sweeper looks for a room that is due. Most passes find none and ask the
/// VTA nothing.
const TICK: Duration = Duration::from_secs(300);
/// The first pass waits this long after boot, so the messaging link has had time to come up.
const FIRST_PASS: Duration = Duration::from_secs(60);
/// The first retry's ceiling, doubling per failure up to [`RETRY_CAP`].
const RETRY_BASE: Duration = Duration::from_secs(60);
const RETRY_CAP: Duration = Duration::from_secs(6 * 60 * 60);

/// The `admin` authority the community holds in every room it owns, as create issues it.
const OWNER_ACTIONS: [&str; 4] = ["read", "write", "curate", "admin"];

const OWNER_MEMBERSHIP: &str = <owner_membership::Payload as Payload>::TYPE_URI;
const OWNER_AUTHORITY: &str = <owner_authority::Payload as Payload>::TYPE_URI;
const VAULT_RECEIVE: &str = <vault_receive::Payload as Payload>::TYPE_URI;
const VAULT_QUERY: &str = <vault_query::Payload as Payload>::TYPE_URI;
const VAULT_GET: &str = <vault_get::Payload as Payload>::TYPE_URI;

/// The VC `type` tags the two credentials carry, as the VTA files them.
const MEMBERSHIP_TYPE: &str = "MembershipCredential";
const AUTHORITY_TYPE: &str = "AuthorityCredential";

fn record_key(room_id: &str) -> Vec<u8> {
    format!("authority-renewal:{room_id}").into_bytes()
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// What this community knows about renewing one room: where the VTA keeps the community's
/// credentials for it, and how the last attempts went.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RenewalRecord {
    pub room_id: String,
    /// The VTA vault handle of the community's membership credential for the room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_vault_id: Option<String>,
    /// The VTA vault handle of the community's `admin` authority credential for the room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_vault_id: Option<String>,
    /// Failures since the last success; zero when the last attempt succeeded.
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    /// Not before this, after a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    /// Why the last attempt failed, while it is failing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_renewed_at: Option<String>,
}

impl RenewalRecord {
    fn new(room_id: &str) -> Self {
        Self {
            room_id: room_id.to_string(),
            ..Default::default()
        }
    }

    /// What the console is shown about this room's renewal, in
    /// `ext["org.openvtc"].authorityRenewal`.
    pub fn status(&self) -> Value {
        let mut v = json!({ "state": if self.attempts > 0 { "failing" } else { "ok" } });
        if self.attempts > 0 {
            v["attempts"] = json!(self.attempts);
        }
        for (name, field) in [
            ("lastAttemptAt", &self.last_attempt_at),
            ("nextAttemptAt", &self.next_attempt_at),
            ("lastError", &self.last_error),
            ("lastRenewedAt", &self.last_renewed_at),
        ] {
            if let Some(f) = field {
                v[name] = json!(f);
            }
        }
        v
    }
}

/// The renewal record of `room_id`, if this community has one.
pub async fn record(
    rooms: &CommunityRooms,
    room_id: &str,
) -> Result<Option<RenewalRecord>, AppError> {
    rooms.keyspace().get(record_key(room_id)).await
}

async fn put_record(rooms: &CommunityRooms, rec: &RenewalRecord) -> Result<(), AppError> {
    rooms.keyspace().insert(record_key(&rec.room_id), rec).await
}

/// At create: the handles the VTA stored the community's two credentials under, so a
/// renewal can replace them without reading the VTA's vault.
pub async fn record_vault_ids(
    rooms: &CommunityRooms,
    room_id: &str,
    membership_vault_id: String,
    authority_vault_id: String,
) -> Result<(), AppError> {
    let mut rec = record(rooms, room_id)
        .await?
        .unwrap_or_else(|| RenewalRecord::new(room_id));
    rec.membership_vault_id = Some(membership_vault_id);
    rec.authority_vault_id = Some(authority_vault_id);
    put_record(rooms, &rec).await
}

/// `ext["org.openvtc"].authorityRenewal` for one room's `get`.
pub async fn room_ext(state: &AppState, room_id: &str) -> Result<Option<Value>, AppError> {
    let Some(community) = state.config.read().await.rooms.community.clone() else {
        return Ok(None);
    };
    let mut v = record(&state.community_rooms, room_id)
        .await?
        .map(|r| r.status())
        .unwrap_or_else(|| json!({ "state": "ok" }));
    v["renewWithinDays"] = json!(community.authority_renew_within().num_days());
    Ok(Some(v))
}

/// `ext["org.openvtc"].authorityRenewal` for a `list` page: the window, and each listed
/// room this community has a renewal record for, by room DID.
pub async fn list_ext(state: &AppState, room_ids: &[String]) -> Result<Option<Value>, AppError> {
    let Some(community) = state.config.read().await.rooms.community.clone() else {
        return Ok(None);
    };
    let mut rooms = serde_json::Map::new();
    for id in room_ids {
        if let Some(r) = record(&state.community_rooms, id).await? {
            rooms.insert(id.clone(), r.status());
        }
    }
    Ok(Some(json!({
        "renewWithinDays": community.authority_renew_within().num_days(),
        "rooms": rooms,
    })))
}

/// The wait after `attempts` consecutive failures: half the capped exponential ceiling,
/// plus up to the other half at random, so rooms that failed together do not retry together.
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

/// What a pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Rooms renewed.
    pub renewed: Vec<String>,
    /// Rooms whose renewal was attempted and failed.
    pub failed: Vec<String>,
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
                tracing::warn!(error = %e, "community room authority renewal pass failed");
            }
        }
    });
}

/// One pass at `now`: renew every room that is due and not waiting out a failure.
pub async fn sweep(state: &AppState, now: DateTime<Utc>) -> Result<SweepReport, AppError> {
    let mut report = SweepReport::default();
    // Read and released before anything awaits on the VTA.
    let (community, vtc_did) = {
        let config = state.config.read().await;
        (config.rooms.community.clone(), config.vtc_did.clone())
    };
    let (Some(community), Some(vtc_did)) = (community, vtc_did) else {
        return Ok(report);
    };
    // No link: nothing to ask, and nothing failed. A later pass, after a restart that
    // brings the link, renews.
    let Some(holder) = state.community_rooms.key_holder() else {
        return Ok(report);
    };
    let window = community.authority_renew_within();

    for room in state.community_rooms.rooms().await? {
        let Some(until) = parse_time(&room.owner_authority_valid_until) else {
            tracing::warn!(room = %room.room_id, until = %room.owner_authority_valid_until,
                "a community room's authority expiry is unreadable; not renewing it");
            continue;
        };
        if until - now > window {
            continue;
        }
        if !renewable(state, &room, &vtc_did, now).await {
            continue;
        }
        let mut rec = record(&state.community_rooms, &room.room_id)
            .await?
            .unwrap_or_else(|| RenewalRecord::new(&room.room_id));
        if rec
            .next_attempt_at
            .as_deref()
            .and_then(parse_time)
            .is_some_and(|next| next > now)
        {
            continue;
        }

        rec.last_attempt_at = Some(rfc3339(now));
        let new_until = now + chrono::Duration::days(i64::from(community.authority_valid_days()));
        match renew(&holder, &community, &vtc_did, &room, &mut rec, new_until).await {
            Ok(()) => {
                // The one local write, now that the VTA holds both credentials. Re-read, so
                // nothing else on the record is written back stale.
                let mut current = state
                    .community_rooms
                    .room(&room.room_id)
                    .await?
                    .unwrap_or(room.clone());
                current.owner_authority_valid_until = rfc3339(new_until);
                state.community_rooms.put_room(&current).await?;
                let failures = rec.attempts;
                rec.attempts = 0;
                rec.next_attempt_at = None;
                rec.last_error = None;
                rec.last_renewed_at = Some(rfc3339(now));
                put_record(&state.community_rooms, &rec).await?;
                let note = if failures > 0 {
                    format!(
                        "valid until {} (after {failures} failed attempts)",
                        rfc3339(new_until)
                    )
                } else {
                    format!("valid until {}", rfc3339(new_until))
                };
                audit(state, &vtc_did, &room, "authorityRenewed", note).await;
                tracing::info!(room = %room.room_id, until = %rfc3339(new_until),
                    "the community's authority over a room it owns was renewed");
                report.renewed.push(room.room_id.clone());
            }
            Err(why) => {
                rec.attempts = rec.attempts.saturating_add(1);
                rec.next_attempt_at = Some(rfc3339(now + backoff(rec.attempts)));
                rec.last_error = Some(why.clone());
                put_record(&state.community_rooms, &rec).await?;
                if until <= now {
                    tracing::error!(room = %room.room_id, attempts = rec.attempts, error = %why,
                        "the community's authority over a room it owns has lapsed and could not be renewed; it cannot admit or remove until it is");
                } else {
                    tracing::warn!(room = %room.room_id, attempts = rec.attempts, error = %why,
                        until = %room.owner_authority_valid_until,
                        "could not renew the community's authority over a room it owns; will retry");
                }
                if rec.attempts == 1 {
                    audit(state, &vtc_did, &room, "authorityRenewalFailed", why).await;
                }
                report.failed.push(room.room_id.clone());
            }
        }
    }
    Ok(report)
}

/// Whether `room` is still one this community hosts and owns, and not past its retention.
async fn renewable(state: &AppState, room: &OwnedRoom, vtc_did: &str, now: DateTime<Utc>) -> bool {
    match vti_rooms::storage::get_room(&state.rooms_ks, &room.room_id).await {
        Ok(hosted) => {
            hosted.owner_did == vtc_did
                && hosted.lifecycle(now.timestamp().max(0) as u64)
                    != vti_rooms::lifecycle::Lifecycle::Reclaimable
        }
        Err(AppError::NotFound(_)) => false,
        Err(e) => {
            tracing::warn!(room = %room.room_id, error = %e, "could not read a community room; not renewing it now");
            false
        }
    }
}

async fn audit(state: &AppState, actor: &str, room: &OwnedRoom, event: &str, note: String) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let data = CommunityRoomChangedData {
        event: event.to_string(),
        room_id: room.room_id.clone(),
        visibility: room.visibility.clone(),
        member: None,
        actions: Vec::new(),
        epoch: None,
        note: Some(note),
        reason: None,
    };
    if let Err(e) = writer
        .write(actor, None, AuditEvent::CommunityRoomChanged(data))
        .await
    {
        tracing::warn!(error = %e, event, "could not audit a community room authority renewal");
    }
}

// ─── the steps at the VTA ───────────────────────────────────────────────

/// `payload`, read as the generated request type and written back.
fn typed<P: Serialize + DeserializeOwned>(payload: Value) -> Result<Value, String> {
    let p: P = serde_json::from_value(payload)
        .map_err(|e| format!("a request to the community's VTA: {e}"))?;
    serde_json::to_value(p).map_err(|e| e.to_string())
}

/// `answer`, read as the generated response type.
fn read<R: DeserializeOwned>(task: &str, answer: Value) -> Result<R, String> {
    serde_json::from_value(answer).map_err(|e| {
        format!(
            "the community's VTA answered {task} in a shape its specification does not define: {e}"
        )
    })
}

fn holder_error(task: &str, e: HolderError) -> String {
    match e {
        HolderError::Unavailable(m) => format!("{task}: {m}"),
        HolderError::Refused { code, message } => {
            format!("{task}: the community's VTA refused: {code} {message}")
        }
    }
}

async fn ask(holder: &KeyHolder, task: &str, name: &str, payload: Value) -> Result<Value, String> {
    holder
        .ask(task, payload, SIGN_TIMEOUT)
        .await
        .map_err(|e| holder_error(name, e))
}

/// Issue and store a fresh membership and authority for the community in `room`, each
/// replacing the one it renews. Records each handle in `rec` as soon as it is known.
async fn renew(
    holder: &KeyHolder,
    community: &CommunityRoomsConfig,
    vtc_did: &str,
    room: &OwnedRoom,
    rec: &mut RenewalRecord,
    new_until: DateTime<Utc>,
) -> Result<(), String> {
    let until = rfc3339(new_until);
    if rec.membership_vault_id.is_none() {
        rec.membership_vault_id = held(holder, room, vtc_did, MEMBERSHIP_TYPE).await?;
    }
    if rec.authority_vault_id.is_none() {
        rec.authority_vault_id = held(holder, room, vtc_did, AUTHORITY_TYPE).await?;
    }

    let membership = typed::<owner_membership::Payload>(json!({
        "roomId": room.room_id,
        "signingKeyId": room.signing_key_id,
        "subject": vtc_did,
        "validUntil": until,
    }))?;
    let answer = ask(
        holder,
        OWNER_MEMBERSHIP,
        "rooms/owner/issue-membership",
        membership,
    )
    .await?;
    let credential =
        read::<owner_membership::Response>("rooms/owner/issue-membership", answer)?.credential;
    let id = store(
        holder,
        community,
        &credential,
        rec.membership_vault_id.clone(),
    )
    .await?;
    rec.membership_vault_id = Some(id);

    let authority = typed::<owner_authority::Payload>(json!({
        "roomId": room.room_id,
        "signingKeyId": room.signing_key_id,
        "subject": vtc_did,
        "actions": OWNER_ACTIONS,
        "validUntil": until,
    }))?;
    let answer = ask(
        holder,
        OWNER_AUTHORITY,
        "rooms/owner/issue-authority",
        authority,
    )
    .await?;
    let credential =
        read::<owner_authority::Response>("rooms/owner/issue-authority", answer)?.credential;
    let id = store(
        holder,
        community,
        &credential,
        rec.authority_vault_id.clone(),
    )
    .await?;
    rec.authority_vault_id = Some(id);
    Ok(())
}

/// Store `credential` in the VTA's vault, under `id` when it replaces one. Answers the
/// handle it is stored under.
async fn store(
    holder: &KeyHolder,
    community: &CommunityRoomsConfig,
    credential: &str,
    id: Option<String>,
) -> Result<String, String> {
    let credential: Value = serde_json::from_str(credential)
        .map_err(|e| format!("the community's VTA issued a credential that is not JSON: {e}"))?;
    let mut request = json!({ "credential": credential, "contextId": community.context });
    if let Some(id) = id {
        request["id"] = json!(id);
    }
    let request = typed::<vault_receive::Payload>(request)?;
    let answer = ask(holder, VAULT_RECEIVE, "vault/credentials/receive", request).await?;
    Ok(
        read::<vault_receive::Response>("vault/credentials/receive", answer)?
            .id
            .to_string(),
    )
}

/// For a room created before its handles were recorded: the handle of the one credential
/// of `type_tag` the room issued to this community, as the VTA's vault holds it. `None`
/// when it holds none — the renewal then stores a first one.
async fn held(
    holder: &KeyHolder,
    room: &OwnedRoom,
    vtc_did: &str,
    type_tag: &str,
) -> Result<Option<String>, String> {
    let query = typed::<vault_query::Payload>(json!({
        "type": type_tag,
        "issuerDid": room.room_id,
    }))?;
    let answer = holder
        .ask(VAULT_QUERY, query, SIGN_TIMEOUT)
        .await
        .map_err(|e| match e {
            HolderError::Refused { code, message } if code.contains("ermission") || code.contains("orbidden") => format!(
                "vault/credentials/query: the community's VTA refused ({code} {message}). A room \
                 created before this release has no record of where the VTA keeps the \
                 community's credentials for it, and finding them takes `vault-read` on this \
                 community's entry at the VTA: add it (`pnm acl update <community DID> \
                 --capabilities …,vault-read`), or renew by hand with `pnm rooms owner \
                 issue-authority`"
            ),
            other => holder_error("vault/credentials/query", other),
        })?;
    let found = read::<vault_query::Response>("vault/credentials/query", answer)?;
    let mut mine = Vec::new();
    for descriptor in found.credentials {
        let id = descriptor.id.to_string();
        let get = typed::<vault_get::Payload>(json!({ "id": id }))?;
        let answer = ask(holder, VAULT_GET, "vault/credentials/get", get).await?;
        let got = read::<vault_get::Response>("vault/credentials/get", answer)?;
        if got
            .credential
            .get("credentialSubject")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_str)
            == Some(vtc_did)
        {
            mine.push(id);
        }
    }
    match mine.len() {
        0 => Ok(None),
        1 => Ok(mine.pop()),
        n => Err(format!(
            "the community's VTA holds {n} {type_tag}s issued by room `{}` to this community, \
             and acts on the room with none of them until one is left; remove the older \
             (`pnm cred-vault delete`) and this renewal completes on its next attempt",
            room.room_id
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        for attempts in 1..40 {
            let b = backoff(attempts);
            let ceiling = RETRY_BASE
                .saturating_mul(1u32.checked_shl(attempts - 1).unwrap_or(u32::MAX))
                .min(RETRY_CAP)
                .as_secs() as i64;
            assert!(
                b.num_seconds() >= ceiling / 2 && b.num_seconds() <= ceiling,
                "{attempts}: {b}"
            );
        }
        assert!(backoff(1).num_seconds() <= 60);
        assert!(backoff(30).num_seconds() >= 3 * 60 * 60);
    }

    #[test]
    fn the_window_is_never_more_than_half_the_authority_life() {
        let mut c = CommunityRoomsConfig {
            context: "vtc".into(),
            webvh_server: None,
            mediator_did: None,
            authority_valid_days: None,
            authority_renew_within_days: None,
        };
        assert_eq!(c.authority_renew_within(), chrono::Duration::days(30));
        c.authority_renew_within_days = Some(400);
        assert_eq!(c.authority_renew_within(), chrono::Duration::days(365) / 2);
        c.authority_valid_days = Some(1);
        assert_eq!(c.authority_renew_within(), chrono::Duration::hours(12));
    }

    #[test]
    fn a_failing_record_says_so() {
        let mut r = RenewalRecord::new("did:example:room");
        assert_eq!(r.status()["state"], "ok");
        r.attempts = 2;
        r.last_error = Some("no answer".into());
        let s = r.status();
        assert_eq!(s["state"], "failing");
        assert_eq!(s["attempts"], 2);
        assert_eq!(s["lastError"], "no answer");
    }
}
