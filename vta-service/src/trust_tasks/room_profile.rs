//! A room's own profile — `rooms/keys/profile/read/0.1` and `rooms/keys/profile/write/0.1`,
//! and the epoch-advance re-write `rooms/owner/group/{add,remove,renew}` carry.
//!
//! The profile is a record of the room, at a location only a key holder can compute
//! ([`room_groups::profile_location`]) — so a member's surface cannot even find it without
//! this VTA, and checking that whoever wrote it could ([`room_profile::check_statement`]) is
//! chain verification that belongs where the keys are. Both tasks act **as the principal**:
//! every request to the host is issued and signed by the member's persona and carries the
//! persona's own grant, `read` to look and `write` (or `curate`, to clear) to store, and this
//! VTA's own identifier reaches the host nowhere.
//!
//! # Re-written at every advance
//!
//! A profile written under epoch `E` is sealed under `E`. A member who joins later finds it
//! only by walking back, and on a `fromJoin` room cannot. So the owner's key holder — the
//! room's sole committer — reads the profile **before** an advance ([`carry_before_advance`])
//! and writes it again under the new epoch **after** the host accepts it
//! ([`rewrite_after_advance`]), as its principal. Neither may fail, delay or roll back the
//! advance: a membership change is the act, and the profile follows it.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::rooms::keys::profile::{read as spec_read, write as spec_write};
use vti_common::acl::Capability;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::room_groups::{self, Member};
use crate::operations::room_host::RoomTaskError;
use crate::operations::room_oracle::Principal;
use crate::operations::room_profile::{self as profile, ReadAt, Rejected, Rejection, Resolution};
use crate::server::AppState;

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, parse_payload, reject_with_code, success_response};
use super::room_group::{declared, record};

/// How many epochs a read walks down before it stops of its own accord and says so in
/// `searched` (`rooms/keys/profile/read/0.1` item 2 lets it choose). The owner re-writes the
/// profile at every advance, so on the ordinary path it is at the current epoch; a room
/// whose profile is further down than this has not had it re-written for a long time.
const WALK_BOUND: usize = 32;

/// How far down the epochs the read before an advance looks. The owner re-writes the
/// profile at every advance, so where it keeps up the profile is at the current epoch; the
/// bound keeps an advance of a room that has never had a profile from walking its history.
const CARRY_BOUND: usize = 8;

/// How many times a write re-seals for the version the host actually assigned before it
/// answers `contended` (item 6). Versions come from a room-wide counter, so each attempt
/// loses only to a write that landed between this one's seal and its put.
const WRITE_ATTEMPTS: usize = 4;

/// How many times the epoch-advance re-write is tried before it is given up and logged.
const REWRITE_ATTEMPTS: usize = 3;

/// Why the profile could not be read or written, as the two tasks' declared codes name it.
#[derive(Debug)]
pub(super) enum ProfileError {
    NotAMember(String),
    NoAuthority(String),
    HostUnreachable(String),
    HostRefused { code: String, message: String },
    Contended(String),
    App(AppError),
}

impl From<AppError> for ProfileError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAMember(m) | Self::NoAuthority(m) | Self::HostUnreachable(m) => {
                write!(f, "{m}")
            }
            Self::Contended(m) => write!(f, "{m}"),
            Self::HostRefused { code, message } => write!(f, "{code}: {message}"),
            Self::App(e) => write!(f, "{e}"),
        }
    }
}

/// A host refusal, from a [`RoomTaskError`].
fn host_error(host: &str, e: RoomTaskError) -> ProfileError {
    match e {
        RoomTaskError::Refused { code, reason, .. } => ProfileError::HostRefused {
            code,
            message: reason,
        },
        RoomTaskError::Unknown(e) => {
            ProfileError::HostUnreachable(format!("room host `{host}` did not answer: {e}"))
        }
    }
}

/// Whether a host's refusal of `rooms/records/get` says only that no record has the key —
/// an empty profile location, which the walk passes over (`rooms/keys/profile/read/0.1`
/// item 3), rather than a refusal of the read.
///
/// The specification's own code is `rooms/records/get:notFound`; this workspace's hosts
/// answer a missing record as `taskFailed` with the storage layer's "record `…` not found",
/// which is told apart from a room the host does not serve ("room `…` not found").
fn is_empty_location(code: &str, reason: &str) -> bool {
    code.ends_with(":notFound")
        || (code.ends_with("taskFailed") || code.ends_with("task_failed"))
            && reason.contains("record")
            && reason.contains("not found")
}

/// The member a profile task acts as, and what it needs to speak to the room's host as them.
pub(super) struct Speaker<'a> {
    state: &'a AppState,
    auth: &'a AuthClaims,
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &'a str,
    principal: Principal,
    member: Member,
    /// The grants minted so far, by action. A walk fetches one location per epoch, and
    /// minting signs a leaf, so one is minted per action and reused for the request.
    presentations: std::sync::Mutex<std::collections::HashMap<String, Value>>,
}

impl<'a> Speaker<'a> {
    /// The principal persona the caller acts as in `room_id` (or the one `named`), or
    /// `notAMember`.
    pub(super) async fn for_caller(
        state: &'a AppState,
        auth: &'a AuthClaims,
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
        room_id: &str,
        host: &'a str,
        named: Option<&str>,
    ) -> Result<Speaker<'a>, ProfileError> {
        let principal = match crate::operations::room_oracle::principal_named(
            state, auth, room_id, named,
        )
        .await
        {
            Ok(p) => p,
            Err(AppError::NotFound(m)) => return Err(ProfileError::NotAMember(m)),
            Err(e) => return Err(e.into()),
        };
        let member =
            crate::operations::room_member::member_as(state, auth, room_id, &principal.did).await?;
        Ok(Self {
            state,
            auth,
            resolver,
            host,
            principal,
            member,
            presentations: Default::default(),
        })
    }

    /// The owner persona an advance already resolved.
    pub(super) fn for_owner(
        state: &'a AppState,
        auth: &'a AuthClaims,
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
        host: &'a str,
        principal: Principal,
        member: Member,
    ) -> Self {
        Self {
            state,
            auth,
            resolver,
            host,
            principal,
            member,
            presentations: Default::default(),
        }
    }

    fn room_id(&self) -> &str {
        self.member.room_id()
    }

    /// Whether this VTA holds the room's group for the member: a sealed tier. Without one
    /// the room is `open` or the member is not in it, which `rooms/info` tells apart.
    async fn sealed(&self) -> Result<bool, ProfileError> {
        if room_groups::load(&self.state.room_groups_ks, &self.member)
            .await?
            .is_some()
        {
            return Ok(true);
        }
        let info = self
            .send(
                vti_rooms::wire::ROOMS_INFO_TYPE,
                serde_json::json!({ "roomId": self.room_id() }),
                "read",
            )
            .await
            .map_err(|e| host_error(self.host, e))?;
        match info.get("visibility").and_then(Value::as_str) {
            Some("open") => Ok(false),
            _ => Err(ProfileError::NotAMember(format!(
                "this VTA holds no group state for room `{}` for `{}`, so it can neither find \
                 nor open the room's profile",
                self.room_id(),
                self.principal.did
            ))),
        }
    }

    /// One request to the host as the member, carrying the member's own grant narrowed to
    /// `action` — `read` to look, `write` to store, `curate` to retract, and nothing wider.
    async fn send(
        &self,
        task: &str,
        mut payload: Value,
        action: &str,
    ) -> Result<Value, RoomTaskError> {
        payload["presentation"] = self
            .presentation(action)
            .await
            .map_err(RoomTaskError::Unknown)?;
        let document = crate::operations::room_host::build_room_task(
            task,
            self.host,
            &self.principal.did,
            payload,
        );
        crate::operations::room_act::check_schema(&document).map_err(RoomTaskError::Unknown)?;
        let document = crate::operations::room_act::sign_as(
            self.state,
            self.auth,
            &self.principal.did,
            document,
        )
        .await
        .map_err(RoomTaskError::Unknown)?;
        crate::operations::room_host::send_signed_room_task_typed(
            &self.state.room_groups_ks,
            &self.member,
            &crate::operations::outbound::Outbound::from_app_state(self.state, self.resolver),
            self.host,
            document,
            &format!("{task}#response"),
        )
        .await
    }

    /// The principal's own grant narrowed to `action`, granted to the principal — minted
    /// once per action for the life of this request.
    async fn presentation(&self, action: &str) -> Result<Value, AppError> {
        if let Some(p) = self
            .presentations
            .lock()
            .ok()
            .and_then(|m| m.get(action).cloned())
        {
            return Ok(p);
        }
        let minted = crate::operations::room_oracle::present_as(
            self.state,
            self.auth,
            &self.principal,
            &self.principal.did,
            self.room_id(),
            action,
        )
        .await?;
        if let Ok(mut m) = self.presentations.lock() {
            m.insert(action.to_string(), minted.presentation.clone());
        }
        Ok(minted.presentation)
    }

    /// The record at `key`, or `None` for an empty location.
    async fn fetch(
        &self,
        key: &str,
    ) -> Result<Option<vti_rooms::wire::GetRecordResponse>, ProfileError> {
        match self
            .send(
                vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
                serde_json::json!({ "roomId": self.room_id(), "key": key }),
                "read",
            )
            .await
        {
            Ok(reply) => serde_json::from_value(reply).map(Some).map_err(|e| {
                ProfileError::App(AppError::Internal(format!(
                    "room host `{}` served a record this agent cannot read: {e}",
                    self.host
                )))
            }),
            Err(RoomTaskError::Refused { code, reason, .. })
                if is_empty_location(&code, &reason) =>
            {
                Ok(None)
            }
            Err(e) => Err(host_error(self.host, e)),
        }
    }

    /// The host's head version, from a listing narrowed to `key` — what the next write's
    /// version is predicted from.
    async fn head_version(&self, key: &str) -> Result<u64, ProfileError> {
        let reply = self
            .send(
                vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
                serde_json::json!({ "roomId": self.room_id(), "prefix": key, "limit": 1 }),
                "read",
            )
            .await
            .map_err(|e| host_error(self.host, e))?;
        let listing: vti_rooms::wire::ListRecordsResponse =
            serde_json::from_value(reply).map_err(|e| {
                ProfileError::App(AppError::Internal(format!(
                    "room host `{}` served a listing this agent cannot read: {e}",
                    self.host
                )))
            })?;
        // Without a tree the host names no head; the newest version of the location itself
        // is then the best floor there is, and a miss is corrected by the version race.
        Ok(listing.head_version.unwrap_or_else(|| {
            listing
                .records
                .iter()
                .filter_map(|r| r.get("version").and_then(Value::as_u64))
                .max()
                .unwrap_or(0)
        }))
    }

    /// The `verification` member `rooms/keys/read` gives a record, for this one.
    async fn verification(&self, served: &vti_rooms::wire::GetRecordResponse) -> Value {
        let trace = super::room_group::verify_trace(served);
        let head = super::room_group::head_of(
            served.data_commitment.as_ref(),
            served.record_count,
            served.head_version,
        );
        let mut v = serde_json::json!({
            "trace": trace,
            "priorRoots": super::room_group::compare_head(self.state, &self.member, head.as_ref()).await,
            "anchor": super::room_group::compare_anchor(self.state, self.room_id(), head.as_ref()).await,
        });
        if let Some(h) = head {
            v["head"] = h;
        }
        v
    }

    /// Item 2 of `rooms/keys/profile/write/0.1`: `write` to store, and `curate` or `admin`
    /// for readers to accept — or, to clear, `curate`.
    fn may(&self, clear: bool) -> Result<(), ProfileError> {
        let holds = |a: &str| self.principal.confers(a);
        let ok = if clear {
            holds("curate")?
        } else {
            holds("write")? && (holds("curate")? || holds("admin")?)
        };
        if ok {
            return Ok(());
        }
        let held = self.principal.actions().join(", ");
        Err(ProfileError::NoAuthority(if clear {
            format!(
                "clearing room `{}`'s profile takes `curate`; you hold {held}",
                self.room_id()
            )
        } else {
            format!(
                "naming room `{}` takes `write` and `curate` or `admin`; you hold {held}",
                self.room_id()
            )
        }))
    }
}

// ─── Reading ─────────────────────────────────────────────────────────────

/// Resolve the room's profile as `rooms/keys/profile/read/0.1` does: on a sealed tier, the
/// newest accepted profile walking down from the current epoch; on `open`, the one location.
/// Returns the resolution and the `verification` of the record it returned (the profile
/// found, or the retraction), which the response carries with `profile` and on `cleared`.
pub(super) async fn resolve(
    sp: &Speaker<'_>,
    sealed: bool,
    bound: usize,
) -> Result<(Resolution, Option<Value>), ProfileError> {
    let mut res = Resolution {
        status: "absent",
        ..Default::default()
    };
    let mut verification = None;
    let vm_resolver = sp.state.trust_task_vm_resolver();
    let keys = vti_rooms_dtg::DataIntegrityKeys(sp.state.trust_task_vm_resolver());

    if !sealed {
        let key = vti_rooms::profile::OPEN_PROFILE_KEY;
        if let Some(served) = sp.fetch(key).await? {
            let r = &served.record;
            if matches!(r.status, vti_rooms::RecordStatus::Retracted) {
                res.status = "cleared";
                res.version = Some(r.version);
                verification = Some(sp.verification(&served).await);
            } else {
                let body = r
                    .cleartext
                    .as_ref()
                    .and_then(|c| c.get("body"))
                    .and_then(Value::as_str);
                let at = ReadAt {
                    room_id: sp.room_id(),
                    key,
                    version: r.version,
                    located_at: None,
                    sealed_epoch: None,
                    host_author: r.author.as_deref(),
                    updated_at: &r.updated_at,
                };
                let judged = match body {
                    Some(b) => {
                        profile::check_statement(b.as_bytes(), &at, &vm_resolver, &keys).await
                    }
                    None => Err(Rejected {
                        reason: Rejection::Malformed,
                        author: r.author.clone(),
                    }),
                };
                match judged {
                    Ok(accepted) => {
                        res.status = "found";
                        res.version = Some(r.version);
                        res.accepted = Some(accepted);
                        verification = Some(sp.verification(&served).await);
                    }
                    Err(rejected) => res.rejected.push((None, r.version, rejected)),
                }
            }
        }
        return Ok((res, verification));
    }

    let locations =
        room_groups::profile_locations(&sp.state.room_groups_ks, &sp.member, bound).await?;
    let Some(&(current, _)) = locations.first() else {
        return Ok((res, verification));
    };
    let mut reached = current;
    for (epoch, key) in &locations {
        reached = *epoch;
        let Some(served) = sp.fetch(key).await? else {
            continue;
        };
        let r = &served.record;
        // A retraction takes `curate` at the host: somebody entitled to clear the profile
        // did, and the walk stops — the room has no profile.
        if matches!(r.status, vti_rooms::RecordStatus::Retracted) {
            res.status = "cleared";
            res.epoch = Some(*epoch);
            res.version = Some(r.version);
            verification = Some(sp.verification(&served).await);
            break;
        }
        let reject = |reason, author: Option<&str>| Rejected {
            reason,
            author: author.map(str::to_string),
        };
        let Some(sealed_content) = &r.sealed else {
            res.rejected.push((
                Some(*epoch),
                r.version,
                reject(Rejection::Malformed, r.author.as_deref()),
            ));
            continue;
        };
        // Item 2: sealed under the epoch whose key located it. Checked before opening: a
        // record sealed under another epoch was put here by somebody choosing its location.
        if sealed_content.epoch != *epoch {
            res.rejected.push((
                Some(*epoch),
                r.version,
                reject(Rejection::EpochMismatch, r.author.as_deref()),
            ));
            continue;
        }
        // Opened, and its location checked, at the version the body was sealed at — which a
        // curation (a pin, say) moves the record past (`SealedRecord.version`).
        let Ok(sealed_at) = sealed_content.sealed_at(r.version) else {
            res.rejected.push((
                Some(*epoch),
                r.version,
                reject(Rejection::Location, r.author.as_deref()),
            ));
            continue;
        };
        let search = if sealed_content.version.is_some() {
            room_groups::Search::Exact
        } else {
            room_groups::Search::Earlier
        };
        let (plaintext, sealed_at) = match room_groups::open_record_at(
            &sp.state.room_groups_ks,
            &sp.member,
            key,
            sealed_at,
            &sealed_content.ciphertext,
            &sealed_content.nonce,
            sealed_content.epoch,
            search,
        )
        .await
        {
            Ok(opened) => opened,
            // The AEAD binds room, key, version and epoch: a record that does not open here
            // was not sealed for this location — a version race lost, or a copy.
            Err(_) => {
                res.rejected.push((
                    Some(*epoch),
                    r.version,
                    reject(Rejection::Location, r.author.as_deref()),
                ));
                continue;
            }
        };
        let at = ReadAt {
            room_id: sp.room_id(),
            key,
            version: sealed_at,
            located_at: Some(*epoch),
            sealed_epoch: Some(sealed_content.epoch),
            host_author: r.author.as_deref(),
            updated_at: &r.updated_at,
        };
        match profile::check_statement(&plaintext, &at, &vm_resolver, &keys).await {
            Ok(accepted) => {
                res.status = "found";
                res.epoch = Some(*epoch);
                res.version = Some(r.version);
                res.stale = *epoch < current;
                res.accepted = Some(accepted);
                verification = Some(sp.verification(&served).await);
                break;
            }
            Err(rejected) => {
                if rejected.reason.is_attempted_rename() {
                    tracing::warn!(
                        room = %sp.room_id(),
                        epoch,
                        version = r.version,
                        reason = rejected.reason.as_str(),
                        "a room profile was written by somebody without the standing to name \
                         the room; it is ignored"
                    );
                }
                res.rejected.push((Some(*epoch), r.version, rejected));
            }
        }
    }
    res.searched = Some((current, reached));
    Ok((res, verification))
}

/// The declared codes a profile task refuses with, in its own namespace.
struct Codes {
    not_a_member: trust_tasks_rs::DeclaredErrorCode,
    host_unreachable: trust_tasks_rs::DeclaredErrorCode,
    host_refused: trust_tasks_rs::DeclaredErrorCode,
    no_authority: Option<trust_tasks_rs::DeclaredErrorCode>,
    contended: Option<trust_tasks_rs::DeclaredErrorCode>,
}

const READ_CODES: Codes = Codes {
    not_a_member: spec_read::v0_1::error_codes::NOT_A_MEMBER,
    host_unreachable: spec_read::v0_1::error_codes::HOST_UNREACHABLE,
    host_refused: spec_read::v0_1::error_codes::HOST_REFUSED,
    no_authority: None,
    contended: None,
};

const WRITE_CODES: Codes = Codes {
    not_a_member: spec_write::v0_1::error_codes::NOT_A_MEMBER,
    host_unreachable: spec_write::v0_1::error_codes::HOST_UNREACHABLE,
    host_refused: spec_write::v0_1::error_codes::HOST_REFUSED,
    no_authority: Some(spec_write::v0_1::error_codes::NO_AUTHORITY),
    contended: Some(spec_write::v0_1::error_codes::CONTENDED),
};

fn refuse(doc: &TrustTask<Value>, codes: &Codes, e: ProfileError) -> TrustTaskOutcome {
    let bounded = |s: &str, max: usize| s.chars().take(max).collect::<String>();
    match e {
        ProfileError::NotAMember(m) => reject_with_code(doc, declared(codes.not_a_member), m, None),
        ProfileError::HostUnreachable(m) => {
            reject_with_code(doc, declared(codes.host_unreachable), m, None)
        }
        ProfileError::HostRefused { code, message } => reject_with_code(
            doc,
            declared(codes.host_refused),
            format!("the room's host declined: {code}: {message}"),
            Some(serde_json::json!({
                "code": bounded(&code, 256),
                "message": bounded(&message, 500),
            })),
        ),
        ProfileError::NoAuthority(m) => match codes.no_authority {
            Some(c) => reject_with_code(doc, declared(c), m, None),
            None => app_error_to_reject(doc, AppError::Forbidden(m)),
        },
        ProfileError::Contended(m) => match codes.contended {
            Some(c) => reject_with_code(doc, declared(c), m, None),
            None => app_error_to_reject(doc, AppError::Conflict(m)),
        },
        ProfileError::App(e) => app_error_to_reject(doc, e),
    }
}

/// The member a request names in `ext["org.openvtc.rooms"].member`, or a malformed-request
/// refusal.
#[allow(clippy::result_large_err)]
fn named_member(doc: &TrustTask<Value>) -> Result<Option<String>, TrustTaskOutcome> {
    crate::operations::room_member::named_member(&doc.payload)
        .map_err(super::helpers::malformed_request_response)
}

/// `rooms/keys/profile/read/0.1`.
pub(super) async fn handle_read(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "reading a room's profile",
    )
    .await
    {
        return r;
    }
    let req: spec_read::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();
    let resolver = match super::room_group::outbound_resolver(state, &doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    let outcome = async {
        let sp =
            Speaker::for_caller(state, auth, &resolver, &room_id, &host, named.as_deref()).await?;
        let sealed = sp.sealed().await?;
        resolve(&sp, sealed, WALK_BOUND).await
    }
    .await;
    let (resolution, verification) = match outcome {
        Ok(v) => v,
        Err(e) => return refuse(&doc, &READ_CODES, e),
    };

    let mut payload = resolution.to_payload(&room_id);
    if let Some(v) = verification {
        payload["verification"] = v;
    }
    // The room only: what it is called is not the audit trail's to keep.
    record(state, "rooms.keys.profile.read", auth, &room_id).await;
    success_response(&doc, payload)
}

// ─── Writing ─────────────────────────────────────────────────────────────

/// Where a profile was written.
#[derive(Debug, Clone)]
pub(super) struct Written {
    pub key: String,
    pub version: u64,
    pub epoch: Option<u32>,
}

/// Write `profile` as the room's profile at the current epoch's location (sealed) or at
/// `room-profile` (`open`), signed as the principal, re-sealing for the version the host
/// actually assigned until it lands (`rooms/keys/profile/write/0.1` items 3–6).
pub(super) async fn write(
    sp: &Speaker<'_>,
    sealed: bool,
    profile_value: &Value,
) -> Result<Written, ProfileError> {
    let state = sp.state;
    let (key, epoch) = if sealed {
        let (k, e) = room_groups::profile_location(&state.room_groups_ks, &sp.member, None).await?;
        (k, Some(e))
    } else {
        (vti_rooms::profile::OPEN_PROFILE_KEY.to_string(), None)
    };
    let authority = sp.principal.authority_chain()?;
    let signing_key = crate::operations::persona::persona_key_for(
        crate::operations::persona::PersonaStores::from_state(state),
        sp.auth,
        &sp.principal.did,
        crate::operations::persona::Relationship::AssertionMethod,
    )
    .await?
    .ok_or_else(|| {
        ProfileError::NotAMember(format!(
            "this VTA holds no assertion key for `{}` that you may sign with",
            sp.principal.did
        ))
    })?;
    let name = profile_value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let mut intended = sp.head_version(&key).await? + 1;
    let mut expected: Option<u64> = None;
    let mut landed = 0;
    for _ in 0..WRITE_ATTEMPTS {
        let body = profile::statement_body(
            sp.room_id(),
            &key,
            intended,
            &sp.principal.did,
            profile_value,
            chrono::Utc::now(),
            authority.clone(),
        );
        let signed = profile::sign_padded(body, |b| {
            let key = signing_key.clone();
            async move { super::room_act::sign_body(state, sp.auth, key, b).await }
        })
        .await?;

        let mut payload = serde_json::json!({ "roomId": sp.room_id(), "key": key });
        if sealed {
            let s = room_groups::seal_record(
                &state.room_groups_ks,
                &sp.member,
                &key,
                intended,
                &signed,
            )
            .await?;
            payload["sealed"] = serde_json::json!({
                "ciphertext": s.ciphertext, "nonce": s.nonce, "epoch": s.epoch,
            });
        } else {
            let body = String::from_utf8(signed).map_err(|e| {
                ProfileError::App(AppError::Internal(format!("the signed body: {e}")))
            })?;
            payload["cleartext"] = serde_json::json!({ "title": name, "body": body });
        }
        if let Some(v) = expected {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        let reply = sp
            .send(vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE, payload, "write")
            .await
            .map_err(|e| host_error(sp.host, e))?;
        let put: vti_rooms::wire::PutRecordResponse =
            serde_json::from_value(reply).map_err(|e| {
                ProfileError::App(AppError::Internal(format!(
                    "room host `{}` answered a put this agent cannot read: {e}",
                    sp.host
                )))
            })?;
        landed = put.version;
        if landed == intended {
            return Ok(Written {
                key,
                version: landed,
                epoch,
            });
        }
        // Another write took the predicted version: the record stored is sealed and signed
        // for another one, so it does not open. Write it again, and only over what just
        // landed.
        expected = Some(landed);
        intended = landed + 1;
    }
    Err(ProfileError::Contended(format!(
        "other writes to room `{}` kept landing between sealing its profile and storing it; \
         the record at `{key}` (version {landed}) does not open, and readers fall back to the \
         profile before it. Retrying is safe",
        sp.room_id()
    )))
}

/// Clear the room's profile: retract the record at the current epoch's location, storing
/// one there first when it holds none — a profile is required to retract (item 7).
pub(super) async fn clear(sp: &Speaker<'_>, sealed: bool) -> Result<Written, ProfileError> {
    let (key, epoch) = if sealed {
        let (k, e) =
            room_groups::profile_location(&sp.state.room_groups_ks, &sp.member, None).await?;
        (k, Some(e))
    } else {
        (vti_rooms::profile::OPEN_PROFILE_KEY.to_string(), None)
    };

    let version = match sp.fetch(&key).await? {
        Some(served) if matches!(served.record.status, vti_rooms::RecordStatus::Retracted) => {
            return Ok(Written {
                key,
                version: served.record.version,
                epoch,
            });
        }
        Some(served) => served.record.version,
        None => {
            // The current profile if there is one — so a reader that predates the
            // retraction sees nothing new — else the least profile there is.
            let (found, _) = resolve(sp, sealed, WALK_BOUND).await?;
            let carried = found
                .accepted
                .map(|a| a.profile)
                .unwrap_or_else(|| serde_json::json!({ "name": "-" }));
            write(sp, sealed, &carried).await?.version
        }
    };

    let reply = sp
        .send(
            vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
            serde_json::json!({
                "roomId": sp.room_id(),
                "key": key,
                "status": "retracted",
                "expectedVersion": version,
            }),
            "curate",
        )
        .await
        .map_err(|e| host_error(sp.host, e))?;
    let curated: vti_rooms::wire::CurateRecordResponse =
        serde_json::from_value(reply).map_err(|e| {
            ProfileError::App(AppError::Internal(format!(
                "room host `{}` answered a curation this agent cannot read: {e}",
                sp.host
            )))
        })?;
    Ok(Written {
        key,
        version: curated.version,
        epoch,
    })
}

/// `rooms/keys/profile/write/0.1`.
pub(super) async fn handle_write(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "setting a room's profile",
    )
    .await
    {
        return r;
    }
    // Signs as the principal: a delegate holding narrower standing writes, if at all, as
    // its own author with its own key holder (*Authorization*).
    if let Err(r) = super::room_act::require_not_delegate(state, auth, &doc).await {
        return r;
    }
    // Parsed through the generated type, which holds the schema's bounds on the profile and
    // its one-of `profile` / `clear`.
    if let Err(resp) = parse_payload::<spec_write::v0_1::Payload>(&doc) {
        return resp;
    }
    let (Some(room_id), Some(host)) = (
        doc.payload.get("roomId").and_then(Value::as_str),
        doc.payload.get("host").and_then(Value::as_str),
    ) else {
        return app_error_to_reject(
            &doc,
            AppError::Validation("`roomId` and `host` are required".into()),
        );
    };
    let room_id = room_id.to_string();
    let host = host.to_string();
    let profile_value = doc.payload.get("profile").cloned();
    let clearing = doc.payload.get("clear").and_then(Value::as_bool) == Some(true);
    if clearing == profile_value.is_some() {
        return app_error_to_reject(
            &doc,
            AppError::Validation("send exactly one of `profile` and `clear`".into()),
        );
    }
    let resolver = match super::room_group::outbound_resolver(state, &doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    let outcome = async {
        let sp =
            Speaker::for_caller(state, auth, &resolver, &room_id, &host, named.as_deref()).await?;
        // Item 2, before the host is contacted: a profile readers would refuse is worse
        // than none.
        sp.may(clearing)?;
        let sealed = sp.sealed().await?;
        match &profile_value {
            Some(p) => write(&sp, sealed, p).await,
            None => clear(&sp, sealed).await,
        }
    }
    .await;
    let written = match outcome {
        Ok(w) => w,
        Err(e) => return refuse(&doc, &WRITE_CODES, e),
    };

    record(
        state,
        if clearing {
            "rooms.keys.profile.clear"
        } else {
            "rooms.keys.profile.write"
        },
        auth,
        &room_id,
    )
    .await;
    let mut payload = serde_json::json!({
        "roomId": room_id,
        "outcome": if clearing { "cleared" } else { "written" },
        "key": written.key,
        "version": written.version,
    });
    if let Some(e) = written.epoch {
        payload["epoch"] = serde_json::json!(e);
    }
    success_response(&doc, payload)
}

// ─── The epoch-advance re-write ──────────────────────────────────────────

/// Before an advance: the room's current profile, where there is one this owner may write
/// again (`rooms/keys/profile/write/0.1`, *Keeping the profile readable across epochs*,
/// items 1, 2 and 4). `None` when the room has none (`absent`), it was deliberately cleared
/// (`cleared`), the owner could not re-write it, or reading it failed — none of which may
/// touch the advance, so a failure is logged and nothing more.
pub(super) async fn carry_before_advance(sp: &Speaker<'_>) -> Option<Value> {
    if sp.may(false).is_err() {
        return None;
    }
    match resolve(sp, true, CARRY_BOUND).await {
        Ok((res, _)) if res.status == "found" => res.accepted.map(|a| a.profile),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                room = %sp.room_id(),
                error = %e,
                "could not read the room's profile before advancing its epoch; it will not be \
                 re-written under the new one"
            );
            None
        }
    }
}

/// After the host accepted an advance: write `carried` again under the new epoch, as the
/// principal — the statement is theirs, signed now; the earlier author's stays where it was,
/// never retracted (item 5). Tried a few times, then logged: never an error, never a delay
/// the advance waits on beyond these attempts (item 3).
pub(super) async fn rewrite_after_advance(sp: &Speaker<'_>, carried: Option<Value>) {
    let Some(carried) = carried else {
        return;
    };
    let mut last = None;
    for _ in 0..REWRITE_ATTEMPTS {
        match write(sp, true, &carried).await {
            Ok(w) => {
                record(
                    sp.state,
                    "rooms.keys.profile.rewrite",
                    sp.auth,
                    sp.room_id(),
                )
                .await;
                tracing::debug!(room = %sp.room_id(), epoch = ?w.epoch, "re-wrote the room's profile under the new epoch");
                return;
            }
            Err(e) => last = Some(e),
        }
    }
    if let Some(e) = last {
        tracing::warn!(
            room = %sp.room_id(),
            error = %e,
            "the room advanced, and re-writing its profile under the new epoch failed; members \
             who joined at this epoch read the profile as stale or absent until it is written \
             again (rooms/keys/profile/write)"
        );
    }
}

#[cfg(test)]
#[path = "room_profile_tests.rs"]
mod tests;
