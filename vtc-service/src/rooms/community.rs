//! Rooms the community **owns** — the owner's half of `vtc/rooms/community/*` and
//! `vtc/rooms/offers/*` (`docs/05-design-notes/data-rooms-files.md` §8.4).
//!
//! # Who holds what
//!
//! The community is the owner of these rooms and **its own VTA is their key holder**: the
//! VTA mints each room's DID from the `room` template, signs the room's credentials and
//! holds the community's place in a sealed room's MLS group. This service holds no room
//! key and no group secret. It acts on a room exactly as any owner's client does — by
//! sending its VTA the `rooms/owner/*` tasks the VTA serves for every owner — over the
//! messaging link it already keeps ([`crate::vta_link`], TSP > DIDComm, the VTA reached
//! through its mediator and never inbound), signed as this community. The VTA applies its
//! own gates to every call: this community's entry there, the context's signing policy.
//!
//! # The owner's record is not the host's
//!
//! The same service also hosts the room. Invariant I5 keeps the **host** from consulting
//! membership: a community room's records are authorized by credential chains exactly as a
//! member's room's are, and nothing on the host path ([`super::handlers`]) reads this
//! module. What lives here — whom the community offered admission to and admitted — is what
//! an owner knows anyway, because it signed their credentials. It is in its own keyspace
//! ([`crate::store::keyspaces::COMMUNITY_ROOMS`]) so the separation is structural.
//!
//! # A room's identity, published
//!
//! A room's DID has to resolve before anyone can verify what it issued — the VTA checks the
//! community's own credentials as it stores them. With `[rooms.community] webvh_server` the
//! VTA publishes each room's log on that hosting server. Without it the room's DID is
//! minted serverless at `<public_url>/room-dids/<id>/did.jsonl`, and this service serves
//! that log ([`serve_room_did_log`]) — the VTA answers a serverless create with the log
//! for the caller to serve (`webvh/dids/create/1.1`).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::vta_storage::{PeerError, VtaChannel};
use crate::server::AppState;

/// The declared codes this module's tasks answer with, named once for the handlers and
/// the error-code census.
pub mod codes {
    use trust_tasks_rs::specs::vtc::rooms::community::{
        create::v0_1 as create, get::v0_1 as get, members::add::v0_1 as add,
        members::list::v0_1 as members_list, members::remove::v0_1 as remove,
    };
    use trust_tasks_rs::specs::vtc::rooms::offers::{accept::v0_1 as accept, list::v0_1 as list};

    pub const CREATE_VISIBILITY_NOT_PERMITTED: &str =
        create::error_codes::VISIBILITY_NOT_PERMITTED.code;
    pub const CREATE_UNKNOWN_STORAGE_CONFIG: &str =
        create::error_codes::UNKNOWN_STORAGE_CONFIG.code;
    pub const CREATE_NO_KEY_HOLDER: &str = create::error_codes::NO_KEY_HOLDER.code;
    pub const CREATE_KEY_HOLDER_UNAVAILABLE: &str =
        create::error_codes::KEY_HOLDER_UNAVAILABLE.code;
    pub const CREATE_KEY_HOLDER_REFUSED: &str = create::error_codes::KEY_HOLDER_REFUSED.code;
    pub const GET_NOT_FOUND: &str = get::error_codes::NOT_FOUND.code;
    pub const ADD_NOT_FOUND: &str = add::error_codes::NOT_FOUND.code;
    pub const ADD_NOT_A_MEMBER: &str = add::error_codes::NOT_A_MEMBER.code;
    pub const ADD_ALREADY_MEMBER: &str = add::error_codes::ALREADY_MEMBER.code;
    pub const ADD_KEY_HOLDER_UNAVAILABLE: &str = add::error_codes::KEY_HOLDER_UNAVAILABLE.code;
    pub const ADD_KEY_HOLDER_REFUSED: &str = add::error_codes::KEY_HOLDER_REFUSED.code;
    pub const REMOVE_NOT_FOUND: &str = remove::error_codes::NOT_FOUND.code;
    pub const REMOVE_NOT_IN_ROOM: &str = remove::error_codes::NOT_IN_ROOM.code;
    pub const REMOVE_KEY_HOLDER_UNAVAILABLE: &str =
        remove::error_codes::KEY_HOLDER_UNAVAILABLE.code;
    pub const REMOVE_KEY_HOLDER_REFUSED: &str = remove::error_codes::KEY_HOLDER_REFUSED.code;
    pub const MEMBERS_LIST_NOT_FOUND: &str = members_list::error_codes::NOT_FOUND.code;
    pub const OFFERS_LIST_NOT_A_MEMBER: &str = list::error_codes::NOT_A_MEMBER.code;
    pub const ACCEPT_NOT_FOUND: &str = accept::error_codes::NOT_FOUND.code;
    pub const ACCEPT_NOT_A_MEMBER: &str = accept::error_codes::NOT_A_MEMBER.code;
    pub const ACCEPT_OFFER_EXPIRED: &str = accept::error_codes::OFFER_EXPIRED.code;
    pub const ACCEPT_KEY_PACKAGE_REQUIRED: &str = accept::error_codes::KEY_PACKAGE_REQUIRED.code;
    pub const ACCEPT_KEY_PACKAGE_NOT_EXPECTED: &str =
        accept::error_codes::KEY_PACKAGE_NOT_EXPECTED.code;
    pub const ACCEPT_KEY_PACKAGE_INVALID: &str = accept::error_codes::KEY_PACKAGE_INVALID.code;
    pub const ACCEPT_ALREADY_ACCEPTED: &str = accept::error_codes::ALREADY_ACCEPTED.code;
    pub const ACCEPT_ADMISSION_PENDING: &str = accept::error_codes::ADMISSION_PENDING.code;
    pub const ACCEPT_KEY_HOLDER_REFUSED: &str = accept::error_codes::KEY_HOLDER_REFUSED.code;
}

/// How long the VTA has to answer a step that only signs (mint, issue, store).
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the VTA has to answer a step that advances the room at its host — this
/// service — and so makes a round trip of its own before it answers.
pub const ADVANCE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a Welcome is kept after an acceptance, to answer a repeated accept carrying
/// the same KeyPackage (`vtc/rooms/offers/accept` *Repeating an accept*). It matches the
/// life of the KeyPackage it is sealed to: a member's VTA discards an unused one after
/// seven days, so a Welcome kept longer could open nothing.
pub const WELCOME_KEPT: chrono::Duration = chrono::Duration::days(7);

/// The path a serverless room identity's log is served under: `/room-dids/<id>/did.jsonl`.
pub const ROOM_DID_PATH: &str = "room-dids";

/// A room the community owns, as the owner records it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedRoom {
    pub room_id: String,
    pub label: String,
    /// `open`, `attributed` or `private`.
    pub visibility: String,
    /// The key the community's VTA signs as the room with — the `room` template's
    /// `#key-1`. Named on every `rooms/owner/*` call: nothing at the VTA maps a room's DID
    /// to its key.
    pub signing_key_id: String,
    /// The administrator who created it.
    pub created_by: String,
    /// RFC 3339.
    pub created_at: String,
    /// When the community's own `admin` authority over the room expires, RFC 3339.
    pub owner_authority_valid_until: String,
    /// The `<id>` this service serves the room's log under, for a serverless identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_path: Option<String>,
}

/// The three credentials issued to a member, kept for them to collect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OfferCredentials {
    pub invitation: String,
    pub membership: String,
    pub authority: String,
}

/// The Welcome an acceptance produced, kept to answer a repeat with the same KeyPackage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeptWelcome {
    /// SHA-256 of the KeyPackage as sent (its base64url text), hex.
    pub key_package_digest: String,
    pub welcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// The room epoch the member joined at.
    pub epoch: u64,
}

/// One party offered admission to, or admitted to, a room the community owns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemberRecord {
    pub room_id: String,
    pub member: String,
    /// `read`, `write`, `curate` — never `admin`.
    pub actions: Vec<String>,
    /// RFC 3339: when the member's authority credential expires.
    pub valid_until: String,
    /// `offered`, `admitted` or `removed`.
    pub state: String,
    pub offered_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<String>,
    /// The offer's credentials. Dropped when the member is removed or the offer withdrawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<OfferCredentials>,
    /// The Welcome of a sealed-tier acceptance, while a repeat can still be answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome: Option<KeptWelcome>,
    /// The room epoch the member was admitted at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_epoch: Option<u64>,
}

impl MemberRecord {
    pub const OFFERED: &'static str = "offered";
    pub const ADMITTED: &'static str = "admitted";
    pub const REMOVED: &'static str = "removed";

    /// The `RoomMember` of `vtc/_shared/0.1/community-room`.
    pub fn wire(&self) -> Value {
        let mut v = serde_json::json!({
            "member": self.member,
            "actions": self.actions,
            "validUntil": self.valid_until,
            "state": self.state,
            "offeredAt": self.offered_at,
        });
        if let Some(at) = &self.admitted_at {
            v["admittedAt"] = Value::from(at.clone());
        }
        if let Some(at) = &self.removed_at {
            v["removedAt"] = Value::from(at.clone());
        }
        v
    }

    /// Whether a repeated accept can still be answered from what is kept, at `now`.
    pub fn welcome_kept(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.state == Self::ADMITTED
            && self
                .admitted_at
                .as_deref()
                .and_then(|a| chrono::DateTime::parse_from_rfc3339(a).ok())
                .is_some_and(|a| now < a.with_timezone(&chrono::Utc) + WELCOME_KEPT)
    }
}

/// The digest a [`KeptWelcome`] is matched on.
pub fn key_package_digest(key_package: &str) -> String {
    hex::encode(Sha256::digest(key_package.as_bytes()))
}

/// A served room identity's log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidLog {
    did: String,
    log: String,
}

/// Why the community's VTA did not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolderError {
    /// No answer, or none this service could read: the outcome is unknown.
    Unavailable(String),
    /// The VTA answered with a refusal — its own code and message.
    Refused { code: String, message: String },
}

impl HolderError {
    /// `details` for a `keyHolderRefused`: the VTA's own code and message, bounded as the
    /// specifications bound them.
    pub fn refused_details(code: &str, message: &str) -> Value {
        serde_json::json!({
            "code": truncate(code, 128),
            "message": truncate(message, 500),
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

/// The community's VTA, as the key holder of the rooms it owns.
#[derive(Clone)]
pub struct KeyHolder(Arc<dyn VtaChannel>);

impl KeyHolder {
    /// Send one Trust Task to the VTA and read its answer: the `#response` payload, or the
    /// refusal named.
    pub async fn ask(
        &self,
        type_uri: &str,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, HolderError> {
        let reply = self
            .0
            .exchange(type_uri, &payload, timeout)
            .await
            .map_err(|e| match e {
                PeerError::Transient(m) => HolderError::Unavailable(format!(
                    "the community's VTA could not be reached: {m}"
                )),
                PeerError::NoMatchingProtocol(m) => HolderError::Unavailable(format!(
                    "the community's VTA shares no transport with this community: {m}"
                )),
            })?;
        if reply.type_uri.slug() == "trust-task-error" {
            return Err(HolderError::Refused {
                code: reply.payload["code"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                message: reply.payload["message"].as_str().unwrap_or("").to_string(),
            });
        }
        if reply.type_uri.to_string() != format!("{type_uri}#response") {
            return Err(HolderError::Unavailable(format!(
                "the community's VTA answered `{}` to `{type_uri}`",
                reply.type_uri
            )));
        }
        Ok(reply.payload)
    }
}

/// The rooms this community owns: the owner's record, and the key holder it acts through.
pub struct CommunityRooms {
    ks: KeyspaceHandle,
    holder: std::sync::RwLock<Option<KeyHolder>>,
    /// Held across a membership change, which is read-check-ask-the-VTA-write: two changes
    /// to the community's rooms never race each other at the VTA, which holds one pending
    /// advance per room.
    write_lock: tokio::sync::Mutex<()>,
}

fn room_key(room_id: &str) -> Vec<u8> {
    format!("room:{room_id}").into_bytes()
}

fn member_prefix(room_id: &str) -> Vec<u8> {
    format!("member:{room_id}\u{0}").into_bytes()
}

fn member_key(room_id: &str, member: &str) -> Vec<u8> {
    let mut k = member_prefix(room_id);
    k.extend_from_slice(member.as_bytes());
    k
}

fn holder_prefix(member: &str) -> Vec<u8> {
    format!("holder:{member}\u{0}").into_bytes()
}

fn holder_key(member: &str, room_id: &str) -> Vec<u8> {
    let mut k = holder_prefix(member);
    k.extend_from_slice(room_id.as_bytes());
    k
}

fn did_log_key(id: &str) -> Vec<u8> {
    format!("didlog:{id}").into_bytes()
}

impl CommunityRooms {
    pub fn new(ks: KeyspaceHandle, holder: Option<Arc<dyn VtaChannel>>) -> Arc<Self> {
        Arc::new(Self {
            ks,
            holder: std::sync::RwLock::new(holder.map(KeyHolder)),
            write_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The keyspace, for the backup.
    pub fn keyspace(&self) -> &KeyspaceHandle {
        &self.ks
    }

    /// Connect the community's VTA.
    pub fn set_key_holder(&self, vta: Arc<dyn VtaChannel>) {
        *self.holder.write().expect("holder lock") = Some(KeyHolder(vta));
    }

    /// The community's VTA, when this service has a link to one.
    pub fn key_holder(&self) -> Option<KeyHolder> {
        self.holder.read().expect("holder lock").clone()
    }

    /// Hold this across a membership change.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().await
    }

    pub async fn room(&self, room_id: &str) -> Result<Option<OwnedRoom>, AppError> {
        self.ks.get(room_key(room_id)).await
    }

    pub async fn put_room(&self, room: &OwnedRoom) -> Result<(), AppError> {
        self.ks.insert(room_key(&room.room_id), room).await?;
        // A hint only: an open console re-reads what it shows (`admin_events`).
        crate::admin_events::notify(crate::admin_events::Topic::Rooms);
        Ok(())
    }

    /// Every room the community owns, by identifier.
    pub async fn rooms(&self) -> Result<Vec<OwnedRoom>, AppError> {
        let mut out = Vec::new();
        for (_, raw) in self.ks.prefix_iter_raw(b"room:".to_vec()).await? {
            out.push(serde_json::from_slice::<OwnedRoom>(&raw)?);
        }
        out.sort_by(|a, b| a.room_id.cmp(&b.room_id));
        Ok(out)
    }

    pub async fn member(
        &self,
        room_id: &str,
        member: &str,
    ) -> Result<Option<MemberRecord>, AppError> {
        self.ks.get(member_key(room_id, member)).await
    }

    /// Store a member's record, and the index the member's own listing reads.
    pub async fn put_member(&self, record: &MemberRecord) -> Result<(), AppError> {
        self.ks
            .insert(member_key(&record.room_id, &record.member), record)
            .await?;
        self.ks
            .insert(holder_key(&record.member, &record.room_id), &true)
            .await?;
        crate::admin_events::notify(crate::admin_events::Topic::Rooms);
        Ok(())
    }

    /// Every member record of a room, by member DID.
    pub async fn members(&self, room_id: &str) -> Result<Vec<MemberRecord>, AppError> {
        let mut out = Vec::new();
        for (_, raw) in self.ks.prefix_iter_raw(member_prefix(room_id)).await? {
            out.push(serde_json::from_slice::<MemberRecord>(&raw)?);
        }
        out.sort_by(|a, b| a.member.cmp(&b.member));
        Ok(out)
    }

    /// Every record naming `member`, across the rooms the community owns, by room.
    pub async fn records_of(&self, member: &str) -> Result<Vec<MemberRecord>, AppError> {
        let prefix = holder_prefix(member);
        let mut out = Vec::new();
        for key in self.ks.prefix_keys(prefix.clone()).await? {
            let Ok(room_id) = std::str::from_utf8(&key[prefix.len()..]) else {
                continue;
            };
            if let Some(r) = self.member(room_id, member).await? {
                out.push(r);
            }
        }
        out.sort_by(|a, b| a.room_id.cmp(&b.room_id));
        Ok(out)
    }

    /// `(admitted, offered)`: members in state `admitted`, and offers not yet accepted or
    /// withdrawn.
    pub async fn counts(&self, room_id: &str) -> Result<(u64, u64), AppError> {
        let members = self.members(room_id).await?;
        let count = |s: &str| members.iter().filter(|m| m.state == s).count() as u64;
        Ok((count(MemberRecord::ADMITTED), count(MemberRecord::OFFERED)))
    }

    /// Serve `log` as the `did.jsonl` of `did` under `id`.
    pub async fn put_did_log(&self, id: &str, did: &str, log: &str) -> Result<(), AppError> {
        self.ks
            .insert(
                did_log_key(id),
                &DidLog {
                    did: did.to_string(),
                    log: log.to_string(),
                },
            )
            .await
    }

    pub async fn remove_did_log(&self, id: &str) -> Result<(), AppError> {
        self.ks.remove(did_log_key(id)).await
    }

    async fn did_log(&self, id: &str) -> Result<Option<String>, AppError> {
        Ok(self.ks.get::<DidLog>(did_log_key(id)).await?.map(|l| l.log))
    }
}

/// Whether `id` is a path segment this service could have issued: lower-case hex.
fn plain_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `GET /room-dids/{id}/did.jsonl` — the log of a room identity this community minted
/// serverless. Public, like the community's own `/.well-known/did.jsonl`: a resolver
/// carries no credential, and a `did:webvh` log is published by design.
pub async fn serve_room_did_log(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !plain_id(&id) {
        return (StatusCode::NOT_FOUND, "did log not found").into_response();
    }
    match state.community_rooms.did_log(&id).await {
        Ok(Some(log)) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/jsonl; charset=utf-8"),
            )],
            log,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "did log not found").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read a room identity's log");
            (StatusCode::INTERNAL_SERVER_ERROR, "did log unavailable").into_response()
        }
    }
}

/// Whether `path` is a room identity's log this service may serve: the surface gate lets
/// it through on every host, as it does the community's own log.
pub fn is_room_did_log_path(path: &str) -> bool {
    path.strip_prefix(&format!("/{ROOM_DID_PATH}/"))
        .and_then(|rest| rest.strip_suffix("/did.jsonl"))
        .is_some_and(plain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_issued_ids_are_served() {
        assert!(is_room_did_log_path("/room-dids/0a1b2c/did.jsonl"));
        assert!(!is_room_did_log_path("/room-dids/../did.jsonl"));
        assert!(!is_room_did_log_path("/room-dids/x/y/did.jsonl"));
        assert!(!is_room_did_log_path("/room-dids//did.jsonl"));
        assert!(!is_room_did_log_path("/room-dids/0a1b/other"));
    }

    #[test]
    fn a_welcome_is_kept_for_a_week_after_admission() {
        let now = chrono::Utc::now();
        let mut r = MemberRecord {
            room_id: "did:example:room".into(),
            member: "did:example:m".into(),
            actions: vec!["read".into()],
            valid_until: now.to_rfc3339(),
            state: MemberRecord::ADMITTED.into(),
            offered_at: now.to_rfc3339(),
            admitted_at: Some((now - chrono::Duration::days(6)).to_rfc3339()),
            removed_at: None,
            credentials: None,
            welcome: None,
            admitted_epoch: Some(2),
        };
        assert!(r.welcome_kept(now));
        r.admitted_at = Some((now - chrono::Duration::days(8)).to_rfc3339());
        assert!(!r.welcome_kept(now));
        r.state = MemberRecord::OFFERED.into();
        assert!(!r.welcome_kept(now));
    }
}
