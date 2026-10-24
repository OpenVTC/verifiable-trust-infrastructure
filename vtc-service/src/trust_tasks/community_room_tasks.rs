//! Rooms the community itself owns — `vtc/rooms/community/{create,list,get}/{0.1,0.2}`,
//! `vtc/rooms/community/update/0.1` and `vtc/rooms/community/members/{add,remove,list}/0.1`
//! for its administrators, and `vtc/rooms/offers/list/{0.1,0.2}`,
//! `vtc/rooms/offers/accept/0.1` and `vtc/rooms/memberships/list/0.1` for its members
//! (`docs/05-design-notes/data-rooms-files.md` §8.4; [`crate::rooms::community`]).
//!
//! # Authority
//!
//! | task | signed by | authority (read at execution time) |
//! |---|---|---|
//! | `community/*`, `community/members/*` | an administrator | `vtc.rooms.manage` on the signer's live entry (or a console key's administrator's) |
//! | `offers/list`, `offers/accept`, `memberships/list` | a member | being the member the offer names, and an **active** member now |
//!
//! `vtc.rooms.manage` is the owner's authority, distinct from hosting's `vtc.rooms.admin`.
//! No room-issued credential is required or accepted from an administrator: the community
//! acts on its rooms through its own VTA, which presents the community's own authority.
//!
//! # Step-up, and no parking
//!
//! `create`, `members/add` and `members/remove` take the requester's gesture bound to the
//! one document ([`crate::acl::bound_step_up`]), and are audited with their reason. They
//! are not parked for a second administrator: a room the community owns is its own, its
//! membership is reversible by removal, and nothing here confers authority in the
//! community (the specifications' *model this task is designed for*). This community has
//! no approvals rule list to ask for more; the day it has one, these are its candidates.
//! `update` takes no gesture at all: it reaches no key holder, confers nothing and is
//! undone by itself.
//!
//! # Remote first
//!
//! Every step the VTA takes comes before the one local write, so a failure leaves nothing
//! behind here: a create stores the room only after the VTA minted, founded and issued; an
//! admission is recorded only after the VTA answered with the Welcome; a removal only after
//! the VTA advanced the room. An unknown outcome is said to be one (`keyHolderUnavailable`,
//! `admissionPending`), and the VTA settles its own pending advance on the next request.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::specs::rooms::owner::{
    group::{
        add::v0_1 as owner_add_v0_1, add::v0_2 as owner_add_v0_2, add::v0_3 as owner_add,
        create::v0_1 as owner_group_create,
    },
    invite::v0_1 as owner_invite,
    issue_authority::v0_2 as owner_authority,
    issue_membership::v0_1 as owner_membership,
};
use trust_tasks_rs::specs::vault::credentials::receive::v0_1 as vault_receive;
use trust_tasks_rs::specs::vtc::rooms::community::{
    create::v0_1 as create, create::v0_2 as create_v0_2, create::v0_3 as create_v0_3,
    get::v0_1 as get, get::v0_2 as get_v0_2, list::v0_1 as list, list::v0_2 as list_v0_2,
    members::add::v0_1 as add, members::list::v0_1 as members_list,
    members::remove::v0_1 as remove, members::remove::v0_2 as remove_v0_2, update::v0_1 as update,
    update::v0_2 as update_v0_2,
};
use trust_tasks_rs::specs::vtc::rooms::memberships::list::v0_1 as memberships_list;
use trust_tasks_rs::specs::vtc::rooms::offers::{
    accept::v0_1 as accept, list::v0_1 as offers_list, list::v0_2 as offers_list_v0_2,
    list::v0_3 as offers_list_v0_3,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, CommunityRoomChangedData, FieldChange};
use vti_common::error::AppError;

use super::helpers::{TrustTaskOutcome, app_error_to_reject, reject_with, task_error_to_reject};
use super::storage_tasks::{malformed, refuse, respond};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::error::TaskError;
use crate::rooms::community::{
    ADVANCE_TIMEOUT, HolderError, KeptWelcome, KeyHolder, MemberRecord, OfferCredentials,
    OwnedRoom, ROOM_DID_PATH, SIGN_TIMEOUT, key_package_digest,
};
use crate::rooms::vta_access;
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <create::Payload as Payload>::TYPE_URI;
pub(crate) const CREATE_V0_2_TYPE: &str = <create_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const CREATE_V0_3_TYPE: &str = <create_v0_3::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_V0_2_TYPE: &str = <list_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const GET_TYPE: &str = <get::Payload as Payload>::TYPE_URI;
pub(crate) const GET_V0_2_TYPE: &str = <get_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <update::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_V0_2_TYPE: &str = <update_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_ADD_TYPE: &str = <add::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_REMOVE_TYPE: &str = <remove::Payload as Payload>::TYPE_URI;
/// 0.2: on `open` and `attributed` rooms the member's credentials are withdrawn at the
/// room's host too (trust-tasks-tf #804).
pub(crate) const MEMBERS_REMOVE_V0_2_TYPE: &str = <remove_v0_2::Payload as Payload>::TYPE_URI;

/// The VTA's refusal when an earlier removal it was settling did not take effect
/// (`rooms/owner/group/remove/0.3` item 8.2).
const EARLIER_REMOVAL_REFUSED: &str =
    trust_tasks_rs::specs::rooms::owner::group::remove::v0_3::error_codes::EARLIER_REMOVAL_REFUSED
        .code;
/// The same refusal at an admission (`rooms/owner/group/add/0.3` item 6.1): an earlier
/// removal from the room did not take effect, and nothing of the admission was done.
const ADD_EARLIER_REMOVAL_REFUSED: &str = owner_add::error_codes::EARLIER_REMOVAL_REFUSED.code;
pub(crate) const MEMBERS_LIST_TYPE: &str = <members_list::Payload as Payload>::TYPE_URI;
pub(crate) const OFFERS_LIST_TYPE: &str = <offers_list::Payload as Payload>::TYPE_URI;
pub(crate) const OFFERS_LIST_V0_2_TYPE: &str = <offers_list_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const OFFERS_LIST_V0_3_TYPE: &str = <offers_list_v0_3::Payload as Payload>::TYPE_URI;
pub(crate) const OFFERS_ACCEPT_TYPE: &str = <accept::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERSHIPS_LIST_TYPE: &str = <memberships_list::Payload as Payload>::TYPE_URI;

/// Every URI [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    CREATE_TYPE,
    CREATE_V0_2_TYPE,
    CREATE_V0_3_TYPE,
    LIST_TYPE,
    LIST_V0_2_TYPE,
    GET_TYPE,
    GET_V0_2_TYPE,
    UPDATE_TYPE,
    UPDATE_V0_2_TYPE,
    MEMBERS_ADD_TYPE,
    MEMBERS_REMOVE_TYPE,
    MEMBERS_REMOVE_V0_2_TYPE,
    MEMBERS_LIST_TYPE,
    OFFERS_LIST_TYPE,
    OFFERS_LIST_V0_2_TYPE,
    OFFERS_LIST_V0_3_TYPE,
    OFFERS_ACCEPT_TYPE,
    MEMBERSHIPS_LIST_TYPE,
];

const OWNER_GROUP_CREATE: &str = <owner_group_create::Payload as Payload>::TYPE_URI;
/// `rooms/owner/group/add/0.3`: an earlier removal the VTA settles first is reported as
/// `earlierRemovalRefused`, never as a refusal of this admission (trust-tasks-tf #824).
const OWNER_GROUP_ADD: &str = <owner_add::Payload as Payload>::TYPE_URI;
/// For a VTA that does not serve 0.3: same request, same response, and an earlier removal
/// reported as `hostRefused` with the earlier `member` in its `details`.
const OWNER_GROUP_ADD_V0_2: &str = <owner_add_v0_2::Payload as Payload>::TYPE_URI;
/// For a VTA that does not serve `rooms/owner/group/add/0.2` either: same request, same
/// response, but a repeated admission is refused `alreadyMember` rather than answered (0.2
/// item 8).
const OWNER_GROUP_ADD_V0_1: &str = <owner_add_v0_1::Payload as Payload>::TYPE_URI;
const OWNER_INVITE: &str = <owner_invite::Payload as Payload>::TYPE_URI;
const OWNER_MEMBERSHIP: &str = <owner_membership::Payload as Payload>::TYPE_URI;
const OWNER_AUTHORITY: &str = <owner_authority::Payload as Payload>::TYPE_URI;
const VAULT_RECEIVE: &str = <vault_receive::Payload as Payload>::TYPE_URI;

/// A page when the caller names no `limit` (the specifications' reference value).
const DEFAULT_PAGE: usize = 50;
/// Cursor prefixes: each names the last item of the page it continues.
const ROOMS_CURSOR: &str = "community-rooms:";
const MEMBERS_CURSOR: &str = "community-room-members:";
const OFFERS_CURSOR: &str = "community-room-offers:";
const MEMBERSHIPS_CURSOR: &str = "community-room-memberships:";

use crate::rooms::departures::REMOVAL_NOTICE;

/// Which `vtc/rooms/community/members/remove` is being answered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RemoveVersion {
    /// The group alone, on a sealed tier; nothing withdrawn at the host.
    V0_1,
    /// Withdrawn at the host on `open` and `attributed`; the group too where sealed.
    V0_2,
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CREATE_TYPE => handle_create(state, ctx, doc, CreateAt::V0_1).await,
        CREATE_V0_2_TYPE => handle_create(state, ctx, doc, CreateAt::V0_2).await,
        CREATE_V0_3_TYPE => handle_create(state, ctx, doc, CreateAt::V0_3).await,
        LIST_TYPE => handle_list(state, ctx, doc, Shape::V0_1).await,
        LIST_V0_2_TYPE => handle_list(state, ctx, doc, Shape::V0_2).await,
        GET_TYPE => handle_get(state, ctx, doc, Shape::V0_1).await,
        GET_V0_2_TYPE => handle_get(state, ctx, doc, Shape::V0_2).await,
        UPDATE_TYPE => handle_update(state, ctx, doc, false).await,
        UPDATE_V0_2_TYPE => handle_update(state, ctx, doc, true).await,
        MEMBERS_ADD_TYPE => handle_members_add(state, ctx, doc).await,
        MEMBERS_REMOVE_TYPE => handle_members_remove(state, ctx, doc, RemoveVersion::V0_1).await,
        MEMBERS_REMOVE_V0_2_TYPE => {
            handle_members_remove(state, ctx, doc, RemoveVersion::V0_2).await
        }
        MEMBERS_LIST_TYPE => handle_members_list(state, ctx, doc).await,
        OFFERS_LIST_TYPE => handle_offers_list(state, ctx, doc, OffersShape::V0_1).await,
        OFFERS_LIST_V0_2_TYPE => handle_offers_list(state, ctx, doc, OffersShape::V0_2).await,
        OFFERS_LIST_V0_3_TYPE => handle_offers_list(state, ctx, doc, OffersShape::V0_3).await,
        OFFERS_ACCEPT_TYPE => handle_offers_accept(state, ctx, doc).await,
        MEMBERSHIPS_LIST_TYPE => handle_memberships_list(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── shared ──────────────────────────────────────────────────────────────

/// Which published shape a read or create answers in. `0.1` keeps exactly the shape it
/// published (`CommunityRoom`, `Offer`); `0.2` adds the details administrators keep a room
/// by (`CommunityRoomV2`, `OfferV2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    V0_1,
    V0_2,
}

/// The version of `vtc/rooms/offers/list` being answered: 0.2 adds each room's
/// description, 0.3 the renewals of the admissions the member holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OffersShape {
    V0_1,
    V0_2,
    V0_3,
}

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// `payload`, read as the generated request type and written back: what the VTA is sent
/// is exactly what its specification defines, whatever this file assembled.
fn typed<P: Serialize + DeserializeOwned>(payload: Value) -> Result<Value, AppError> {
    let p: P = serde_json::from_value(payload)
        .map_err(|e| AppError::Internal(format!("a request to the community's VTA: {e}")))?;
    serde_json::to_value(p).map_err(AppError::from)
}

/// `answer`, read as the generated response type.
fn read<R: DeserializeOwned>(task: &str, answer: Value) -> Result<R, HolderError> {
    serde_json::from_value(answer).map_err(|e| {
        HolderError::Unavailable(format!(
            "the community's VTA answered {task} in a shape its specification does not define: {e}"
        ))
    })
}

/// Ask the VTA, as the key holder of the community's rooms.
async fn ask(
    holder: &KeyHolder,
    type_uri: &str,
    payload: Value,
    timeout: std::time::Duration,
) -> Result<Value, HolderError> {
    holder.ask(type_uri, payload, timeout).await
}

/// The requester's gesture bound to this document: `Ok(())` once spent, the refusal
/// asking for it otherwise.
pub(crate) async fn bound_step_up(
    state: &AppState,
    actor: &str,
    doc: &TrustTask<Value>,
    reason: &str,
) -> Result<(), TrustTaskOutcome> {
    use crate::acl::bound_step_up::{self, Gate};
    match bound_step_up::redeem_or_request(
        state,
        actor,
        &doc.type_uri.to_string(),
        &doc.payload,
        reason,
    )
    .await
    {
        Ok(Gate::Satisfied) => Ok(()),
        Ok(Gate::Required(request)) => Err(task_error_to_reject(doc, &TaskError::step_up(request))),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// A refusal the community's entry at its VTA may explain. The operator's log gets the
/// `pnm` commands that fix it ([`vta_access`]): the log is where the VTA's contexts may be
/// said, and the refusal's `message` is not.
async fn refuse_logged(
    state: &AppState,
    doc: &TrustTask<Value>,
    code: &str,
    message: String,
    details: Option<Value>,
) -> TrustTaskOutcome {
    if let Some(facts) = vta_access::Facts::read(state).await
        && let Some(fix) = vta_access::fix_for(&facts, code, &message)
    {
        tracing::warn!(
            code,
            fix = fix.id,
            "a community room operation was refused; the community's entry at its VTA \
             needs a change:\n{}",
            fix.to_text()
        );
    }
    refuse(doc, code, message, details)
}

pub(crate) async fn audit(state: &AppState, actor: &str, data: CommunityRoomChangedData) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let event = data.event.clone();
    if let Err(e) = writer
        .write(actor, None, AuditEvent::CommunityRoomChanged(data))
        .await
    {
        tracing::warn!(error = %e, %event, "could not audit a community room change");
    }
}

pub(crate) fn change(event: &str, room: &OwnedRoom) -> CommunityRoomChangedData {
    CommunityRoomChangedData {
        event: event.to_string(),
        room_id: room.room_id.clone(),
        visibility: room.visibility.clone(),
        member: None,
        actions: Vec::new(),
        epoch: None,
        note: None,
        reason: None,
        details: Vec::new(),
    }
}

/// A room's tags as a set: sorted, each once. `tags` compares as a set (update item 4).
fn tag_set(tags: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = tags.into_iter().collect();
    v.sort();
    v.dedup();
    v
}

/// One detail's audit entry: `old` / `new` absent where it had or has none.
fn detail_change(field: &str, old: Option<Value>, new: Option<Value>) -> FieldChange {
    FieldChange {
        field: field.to_string(),
        old,
        new,
    }
}

fn tags_value(tags: &[String]) -> Option<Value> {
    (!tags.is_empty()).then(|| json!(tags))
}

fn sealed(room: &OwnedRoom) -> bool {
    room.visibility != "open"
}

/// A room the community owns, or the task's `notFound` — which a room it only hosts
/// answers too: its owner is somebody else.
async fn owned(
    state: &AppState,
    doc: &TrustTask<Value>,
    room_id: &str,
    not_found: &str,
) -> Result<OwnedRoom, TrustTaskOutcome> {
    match state.community_rooms.room(room_id).await {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(refuse(
            doc,
            not_found,
            format!("this community owns no room `{room_id}`"),
            None,
        )),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// The `CommunityRoom` of `vtc/_shared/0.1/community-room` — or, at 0.2, its
/// `CommunityRoomV2`, which adds the room's description, tags and who last changed them.
async fn community_room(
    state: &AppState,
    room: &OwnedRoom,
    shape: Shape,
) -> Result<Value, AppError> {
    let hosted = crate::routes::rooms::hosted_room(state, &room.room_id).await?;
    let (admitted, offered) = state.community_rooms.counts(&room.room_id).await?;
    let config = match state.room_storage.assignment(&room.room_id).await? {
        Some(a) => Some(a.config_id),
        None => state.room_storage.default_id().await?,
    };
    let mut v = json!({
        "room": hosted,
        "label": room.label,
        "admitted": admitted,
        "offered": offered,
        "ownerAuthorityValidUntil": room.owner_authority_valid_until,
        "createdBy": room.created_by,
    });
    if let Some(c) = config.filter(|c| !c.is_empty()) {
        v["storageConfig"] = json!(c);
    }
    if shape == Shape::V0_2 {
        if let Some(d) = &room.description {
            v["description"] = json!(d);
        }
        if !room.tags.is_empty() {
            v["tags"] = json!(room.tags);
        }
        // Present together or not at all (`CommunityRoomV2`).
        if let (Some(at), Some(by)) = (&room.details_updated_at, &room.details_updated_by) {
            v["detailsUpdatedAt"] = json!(at);
            v["detailsUpdatedBy"] = json!(by);
        }
    }
    Ok(v)
}

/// A page of `items` after `cursor` (each item's key read by `key`), and the cursor of
/// the next page when there is one. A cursor this community did not issue is refused.
fn page<T>(
    doc: &TrustTask<Value>,
    items: Vec<T>,
    key: impl Fn(&T) -> String,
    prefix: &str,
    cursor: Option<&str>,
    limit: Option<std::num::NonZeroU64>,
) -> Result<(Vec<T>, Option<String>), TrustTaskOutcome> {
    let after = match cursor {
        None => None,
        Some(c) => match c.strip_prefix(prefix) {
            Some(k) if !k.is_empty() => Some(k.to_string()),
            _ => {
                return Err(malformed(
                    doc,
                    "that cursor was not issued by this community",
                ));
            }
        },
    };
    let limit = limit.map(|l| l.get() as usize).unwrap_or(DEFAULT_PAGE);
    let mut rest: Vec<T> = items
        .into_iter()
        .filter(|i| after.as_deref().is_none_or(|a| key(i).as_str() > a))
        .collect();
    let more = rest.len() > limit;
    rest.truncate(limit);
    let next = more
        .then(|| rest.last().map(|l| format!("{prefix}{}", key(l))))
        .flatten();
    Ok((rest, next))
}

// ─── what the community needs to own a room ─────────────────────────────

/// Where a room's identity is published.
enum Publish {
    /// By the VTA, on this hosting server.
    Server(String),
    /// By this service, under its public URL.
    Served { public_url: String },
}

/// Everything a create needs from configuration, or why the community cannot own a room
/// now — a `noKeyHolder`, saying what to add.
struct Setup {
    holder: KeyHolder,
    community_did: String,
    context: String,
    publish: Publish,
    mediator_did: String,
    authority_days: u32,
    /// How the room's identity is presented, as the community states it to its
    /// VTA (VTI-VTC-004).
    presentation: crate::did_hosting::Presentation,
}

async fn setup(state: &AppState) -> Result<Setup, String> {
    let (hosting, presentation) = {
        let config = state.config.read().await.clone();
        let db = crate::config_store::ConfigStore::new(state.config_ks.clone());
        let hosting = crate::did_hosting::live(&config, &db)
            .await
            .map_err(|e| format!("where room identities are published could not be read: {e}"))?;
        let presentation = crate::did_hosting::live_presentation(&config, &db)
            .await
            .map_err(|e| format!("how room identities are presented could not be read: {e}"))?;
        (hosting, presentation)
    };
    let config = state.config.read().await;
    let Some(community) = config.rooms.community.clone() else {
        return Err(
            "this community owns no rooms until its operator turns them on: add a \
                    `[rooms.community]` section naming the context at the community's VTA the \
                    rooms' keys are minted in (`context = \"<context id>\"`), and restart"
                .into(),
        );
    };
    let Some(holder) = state.community_rooms.key_holder() else {
        return Err(
            "this community has no link to a VTA that can hold the room's keys: set \
                    `vta_did`, the community's signing key and `[messaging]`, and restart"
                .into(),
        );
    };
    let Some(community_did) = config.vtc_did.clone() else {
        return Err("this community has no DID yet".into());
    };
    let mediator_did = community
        .mediator_did
        .clone()
        .or_else(|| config.messaging.as_ref().map(|m| m.mediator_did.clone()))
        .filter(|m| !m.is_empty())
        .ok_or_else(|| {
            "a room's DID names a mediator: set `[rooms.community] mediator_did`, or \
             `[messaging] mediator_did`"
                .to_string()
        })?;
    let server =
        crate::did_hosting::server_for(hosting.as_deref(), community.webvh_server.as_deref());
    let publish = match (&server, &config.public_url) {
        (Some(server), _) => Publish::Server(server.clone()),
        (None, Some(url)) => Publish::Served {
            public_url: url.trim_end_matches('/').to_string(),
        },
        (None, None) => {
            return Err(
                "a room's identity is served from this community's public URL unless \
                        `dids.webvh_server` (or `[rooms.community] webvh_server`) names a \
                        hosting server at the VTA: set `public_url`, or `dids.webvh_server`"
                    .into(),
            );
        }
    };
    Ok(Setup {
        holder,
        community_did,
        context: community.context.clone(),
        publish,
        mediator_did,
        authority_days: community.authority_valid_days(),
        presentation,
    })
}

/// The `rooms` policy's answer for a room the community would own, at `visibility`.
async fn govern(
    state: &AppState,
    actor: &str,
    community_did: &str,
    visibility: vti_rooms::Visibility,
    retention_days: Option<u32>,
) -> Result<(), AppError> {
    use crate::rooms::policy as room_policy;
    let member = crate::members::storage::get_member(&state.members_ks, actor)
        .await
        .unwrap_or(None);
    let role = crate::ceremony::assemble::load_actor_role(state, actor)
        .await
        .unwrap_or(None);
    let verified = room_policy::VerifiedRoomCreation::assemble(room_policy::RoomCreationFacts {
        now: Utc::now(),
        actor: room_policy::Actor {
            did: actor.to_string(),
            role,
            member: member.is_some(),
        },
        room: room_policy::RoomRequest {
            room_id: String::new(),
            visibility,
            owner_did: community_did.to_string(),
            retention_days,
            community_owned: true,
        },
    })?;
    let policy = crate::policy::load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        crate::policy::model::PolicyPurpose::Rooms,
    )
    .await
    .map_err(|_| {
        AppError::Forbidden(
            "room creation denied (no-policy): this community has no active `rooms` policy".into(),
        )
    })?;
    room_policy::decide_room_creation(&verified, &policy)
}

// ─── vtc/rooms/community/create ──────────────────────────────────────────

/// How a create failed after the VTA was first asked: its refusal, or an unknown outcome
/// naming the DID it may have minted.
enum CreateFailure {
    Holder(HolderError, Option<String>),
    Local(AppError),
}

/// A create, read from whichever version was sent. 0.1 carries no description or tags.
struct CreateRequest {
    label: String,
    description: Option<String>,
    tags: Vec<String>,
    visibility: String,
    from_join: bool,
    retention_days: Option<std::num::NonZeroU64>,
    storage_config: Option<String>,
    reason: String,
}

impl From<create::Payload> for CreateRequest {
    fn from(p: create::Payload) -> Self {
        Self {
            label: p.label.to_string(),
            description: None,
            tags: Vec::new(),
            visibility: p.visibility.to_string(),
            from_join: matches!(p.retention_policy, Some(create::RetentionPolicy::FromJoin)),
            retention_days: p.retention_days,
            storage_config: p.storage_config.map(|s| s.to_string()),
            reason: p.reason.to_string(),
        }
    }
}

impl From<create_v0_2::Payload> for CreateRequest {
    fn from(p: create_v0_2::Payload) -> Self {
        Self {
            label: p.label.to_string(),
            description: p.description.map(|d| d.to_string()),
            tags: tag_set(p.tags.into_iter().flat_map(|t| t.0).map(|t| t.to_string())),
            visibility: p.visibility.to_string(),
            from_join: matches!(
                p.retention_policy,
                Some(create_v0_2::RetentionPolicy::FromJoin)
            ),
            retention_days: p.retention_days,
            storage_config: p.storage_config.map(|s| s.to_string()),
            reason: p.reason.to_string(),
        }
    }
}

impl From<create_v0_3::Payload> for CreateRequest {
    fn from(p: create_v0_3::Payload) -> Self {
        Self {
            label: p.label.to_string(),
            description: p.description.map(|d| d.to_string()),
            tags: tag_set(p.tags.into_iter().flat_map(|t| t.0).map(|t| t.to_string())),
            visibility: p.visibility.to_string(),
            from_join: matches!(
                p.retention_policy,
                Some(create_v0_3::RetentionPolicy::FromJoin)
            ),
            retention_days: p.retention_days,
            storage_config: p.storage_config.map(|s| s.to_string()),
            reason: p.reason.to_string(),
        }
    }
}

/// Which `vtc/rooms/community/create` is answered. 0.2 and 0.3 answer the same room shape;
/// 0.3 also has the community's VTA write the label and description into the room as its
/// profile (step 5) and says how that went (`roomProfile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateAt {
    V0_1,
    V0_2,
    V0_3,
}

async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: CreateAt,
) -> TrustTaskOutcome {
    let shape = match version {
        CreateAt::V0_1 => Shape::V0_1,
        CreateAt::V0_2 | CreateAt::V0_3 => Shape::V0_2,
    };
    use crate::rooms::community::codes as c;
    let actor = match capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let parsed = match version {
        CreateAt::V0_1 => parse_spec_payload::<create::Payload>(&doc).map(CreateRequest::from),
        CreateAt::V0_2 => parse_spec_payload::<create_v0_2::Payload>(&doc).map(CreateRequest::from),
        CreateAt::V0_3 => parse_spec_payload::<create_v0_3::Payload>(&doc).map(CreateRequest::from),
    };
    let checked = match parsed {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let label = checked.label.clone();
    let visibility: vti_rooms::Visibility = match serde_json::from_value(json!(checked.visibility))
    {
        Ok(v) => v,
        Err(e) => return malformed(&doc, format!("`visibility`: {e}")),
    };
    let retention_policy = if checked.from_join {
        vti_rooms::RetentionPolicy::FromJoin
    } else {
        vti_rooms::RetentionPolicy::Chained
    };
    let retention_days = match checked.retention_days {
        Some(d) => match u32::try_from(d.get()) {
            Ok(d) => Some(d),
            Err(_) => return malformed(&doc, "`retentionDays` is out of range"),
        },
        None => None,
    };

    // Item 5: no key holder, no room — and never a key held here instead.
    let setup = match setup(state).await {
        Ok(s) => s,
        Err(why) => return refuse_logged(state, &doc, c::CREATE_NO_KEY_HOLDER, why, None).await,
    };
    // Item 2.
    if let Err(e) = govern(
        state,
        &actor.did,
        &setup.community_did,
        visibility,
        retention_days,
    )
    .await
    {
        let why = match e {
            AppError::Forbidden(m) => m,
            other => other.to_string(),
        };
        return refuse(&doc, c::CREATE_VISIBILITY_NOT_PERMITTED, why, None);
    }
    // Item 3.
    let storage_config = checked.storage_config.as_ref().map(|s| s.to_string());
    if let Some(id) = &storage_config {
        match state.room_storage.config(id).await {
            Ok(Some(cfg)) if crate::rooms::storage_configs::state_of(&cfg) == "active" => {}
            Ok(_) => {
                return refuse(
                    &doc,
                    c::CREATE_UNKNOWN_STORAGE_CONFIG,
                    format!("no active storage config `{id}`"),
                    None,
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }

    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Create the community room “{label}”"),
    )
    .await
    {
        return reject;
    }

    let authority_until = now() + chrono::Duration::days(i64::from(setup.authority_days));
    let (room_id, signing_key_id, did_path, vault_ids) =
        match mint_and_equip(&setup, &label, visibility, authority_until, state).await {
            Ok(v) => v,
            Err(CreateFailure::Holder(HolderError::Unavailable(why), minted)) => {
                let details = minted.map(|d| json!({ "roomId": d }));
                return refuse(&doc, c::CREATE_KEY_HOLDER_UNAVAILABLE, why, details);
            }
            Err(CreateFailure::Holder(HolderError::Refused { code, message }, _)) => {
                return refuse_logged(
                    state,
                    &doc,
                    c::CREATE_KEY_HOLDER_REFUSED,
                    format!("the community's VTA refused: {code} {message}"),
                    Some(HolderError::refused_details(&code, &message)),
                )
                .await;
            }
            Err(CreateFailure::Local(e)) => return app_error_to_reject(&doc, &e),
        };

    // Item 4: only now, the one local write — the room as its host, owned by the
    // community, then the owner's record of it.
    let at = Utc::now().timestamp().max(0) as u64;
    let room = vti_rooms::Room {
        room_id: room_id.clone(),
        owner_did: setup.community_did.clone(),
        visibility,
        retention_policy,
        anchor_cadence: Default::default(),
        epoch: 1,
        next_version: 1,
        retention_days: retention_days.unwrap_or(90),
        epoch_expires_at: Some(
            at + vti_rooms::lifecycle::DEFAULT_EPOCH_LIFETIME_DAYS as u64 * 24 * 60 * 60,
        ),
        created_at: at,
        updated_at: at,
        mirror_of: None,
        record_retention: None,
        last_prune: None,
        epoch_floor: None,
    };
    if let Err(e) = vti_rooms::storage::create_room(&state.rooms_ks, &room).await {
        return app_error_to_reject(&doc, &e);
    }
    let assigned = match &storage_config {
        Some(id) => {
            let _guard = state.room_storage.lock().await;
            state
                .room_storage
                .write_assignment(&room_id, id, &actor.did)
                .await
        }
        None => state.room_storage.assign_new_room(&room_id).await,
    };
    if let Err(e) = assigned {
        tracing::warn!(room = %room_id, error = %e, "community room not yet assigned a storage config");
    }
    // The details are the owner's record only (create 0.2 item 8): nothing above sent the
    // description or tags anywhere.
    let owned = OwnedRoom {
        room_id: room_id.clone(),
        label: label.clone(),
        visibility: checked.visibility.clone(),
        signing_key_id,
        created_by: actor.did.clone(),
        created_at: rfc3339(now()),
        owner_authority_valid_until: rfc3339(authority_until),
        did_path,
        description: checked.description.clone(),
        tags: checked.tags.clone(),
        details_updated_at: None,
        details_updated_by: None,
    };
    if let Err(e) = state.community_rooms.put_room(&owned).await {
        return app_error_to_reject(&doc, &e);
    }
    // Where the VTA keeps the community's own credentials, so their renewal replaces them
    // (`rooms::community_renewal`). Without it a renewal finds them in the VTA's vault.
    let (membership_id, authority_id) = vault_ids;
    if let Err(e) = crate::rooms::community_renewal::record_vault_ids(
        &state.community_rooms,
        &room_id,
        membership_id,
        authority_id,
    )
    .await
    {
        tracing::warn!(room = %room_id, error = %e, "could not record where the community's room credentials are kept");
    }

    let mut row = change("created", &owned);
    row.reason = Some(checked.reason.clone());
    // The details it starts with, so the trail holds every value a room was ever known by.
    row.details
        .push(detail_change("label", None, Some(json!(owned.label))));
    if let Some(d) = &owned.description {
        row.details
            .push(detail_change("description", None, Some(json!(d))));
    }
    if let Some(t) = tags_value(&owned.tags) {
        row.details.push(detail_change("tags", None, Some(t)));
    }
    audit(state, &actor.did, row).await;
    tracing::info!(room = %room_id, by = %actor.did, "community room created");

    // 0.3 step 5, after the room is stored: the label and description go to the community's
    // own VTA, which seals them into the room as its profile. Never the request's to fail
    // (item 9): `pending` is retried by the profile sweeper.
    let room_profile = match version {
        CreateAt::V0_3 => Some(
            crate::rooms::community_profile::write_now(state, &owned, now())
                .await
                .as_str(),
        ),
        _ => None,
    };

    match community_room(state, &owned, shape).await {
        Ok(room) => match version {
            CreateAt::V0_1 => respond::<create::Response>(&doc, json!({ "room": room })),
            CreateAt::V0_2 => respond::<create_v0_2::Response>(&doc, json!({ "room": room })),
            CreateAt::V0_3 => respond::<create_v0_3::Response>(
                &doc,
                json!({ "room": room, "roomProfile": room_profile }),
            ),
        },
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Steps 1–3 of `vtc/rooms/community/create`, all at the community's VTA: mint the room's
/// DID, found its group on a sealed tier, and issue and store the community's own
/// membership and `admin` authority. Answers the room's DID, its signing key, the path its
/// log is served under when this service serves it, and the VTA vault handles of the
/// membership and the authority.
async fn mint_and_equip(
    setup: &Setup,
    label: &str,
    visibility: vti_rooms::Visibility,
    authority_until: DateTime<Utc>,
    state: &AppState,
) -> Result<(String, String, Option<String>, (String, String)), CreateFailure> {
    let holder = &setup.holder;
    let local = CreateFailure::Local;

    // Step 1: the room's DID, minted from the `room` template, not the context's own.
    let did_path = match &setup.publish {
        Publish::Served { .. } => Some(uuid::Uuid::new_v4().simple().to_string()),
        Publish::Server(_) => None,
    };
    let webvh_server = match &setup.publish {
        Publish::Served { public_url } => public_url.clone(),
        Publish::Server(id) => id.clone(),
    };
    let mut mint = json!({
        "contextId": setup.context,
        "template": "room",
        "templateVars": {
            "WEBVH_SERVER": webvh_server,
            "MEDIATOR_DID": setup.mediator_did,
            "LABEL": label,
        },
        "setPrimary": false,
        "label": format!("Community room: {label}"),
    });
    match (&setup.publish, &did_path) {
        (Publish::Server(id), _) => mint["serverId"] = json!(id),
        (Publish::Served { public_url }, Some(path)) => {
            mint["url"] = json!(format!("{public_url}/{ROOM_DID_PATH}/{path}/did.jsonl"))
        }
        (Publish::Served { .. }, None) => unreachable!("a served identity always has a path"),
    }
    let create_uri = crate::did_hosting::with_presentation(&mut mint, setup.presentation);
    let mint = typed::<vta_sdk::protocols::did_management::create::CreateDidWebvhBody>(mint)
        .map_err(local)?;
    let minted = ask(holder, create_uri, mint, SIGN_TIMEOUT)
        .await
        .map_err(|e| CreateFailure::Holder(e, None))?;
    let minted: vta_sdk::protocols::did_management::create::CreateDidWebvhResultBody =
        read("webvh/dids/create", minted).map_err(|e| CreateFailure::Holder(e, None))?;
    let room_id = crate::did_hosting::presented_did(&minted);
    let signing_key_id = minted.signing_key_id.clone();

    // Served here: published before anything asks the VTA to verify what the room
    // issued, because storing the community's credentials resolves the room's DID.
    if let Some(path) = &did_path {
        let Some(log) = minted.log_entry.as_deref() else {
            return Err(CreateFailure::Holder(
                HolderError::Unavailable(
                    "the community's VTA minted the room's identity serverless and returned no log"
                        .into(),
                ),
                Some(room_id),
            ));
        };
        state
            .community_rooms
            .put_did_log(path, minted.log_did(), log)
            .await
            .map_err(local)?;
    }

    let rest = equip(
        setup,
        &room_id,
        &signing_key_id,
        visibility,
        authority_until,
    )
    .await;
    let vault_ids = match rest {
        Ok(ids) => ids,
        Err(e) => {
            // Nothing is stored for a room that failed; a log served for it would name an
            // identity nobody uses.
            if let Some(path) = &did_path {
                let _ = state.community_rooms.remove_did_log(path).await;
            }
            return Err(CreateFailure::Holder(e, Some(room_id)));
        }
    };
    Ok((room_id, signing_key_id, did_path, vault_ids))
}

/// Steps 2 and 3. Answers the VTA vault handles of the membership and the authority.
async fn equip(
    setup: &Setup,
    room_id: &str,
    signing_key_id: &str,
    visibility: vti_rooms::Visibility,
    authority_until: DateTime<Utc>,
) -> Result<(String, String), HolderError> {
    let holder = &setup.holder;
    let internal = |e: AppError| HolderError::Unavailable(e.to_string());
    // Step 2: the room's group, with the community as its only member.
    if visibility != vti_rooms::Visibility::Open {
        let found = typed::<owner_group_create::Payload>(json!({
            "roomId": room_id,
            "signingKeyId": signing_key_id,
            "member": setup.community_did,
        }))
        .map_err(internal)?;
        let answer = ask(holder, OWNER_GROUP_CREATE, found, SIGN_TIMEOUT).await?;
        read::<owner_group_create::Response>("rooms/owner/group/create", answer)?;
    }
    // Step 3: the community's own membership and `admin` authority, in its VTA's vault.
    let until = rfc3339(authority_until);
    let membership = typed::<owner_membership::Payload>(json!({
        "roomId": room_id,
        "signingKeyId": signing_key_id,
        "subject": setup.community_did,
        "validUntil": until,
    }))
    .map_err(internal)?;
    let authority = typed::<owner_authority::Payload>(json!({
        "roomId": room_id,
        "signingKeyId": signing_key_id,
        "subject": setup.community_did,
        "actions": ["read", "write", "curate", "admin"],
        "validUntil": until,
    }))
    .map_err(internal)?;
    let mut stored = Vec::with_capacity(2);
    for (task, request, name) in [
        (OWNER_MEMBERSHIP, membership, "rooms/owner/issue-membership"),
        (OWNER_AUTHORITY, authority, "rooms/owner/issue-authority"),
    ] {
        let answer = ask(holder, task, request, SIGN_TIMEOUT).await?;
        let credential = read::<owner_membership::Response>(name, answer)?.credential;
        let credential: Value = serde_json::from_str(&credential).map_err(|e| {
            HolderError::Unavailable(format!(
                "{name} answered a credential that is not JSON: {e}"
            ))
        })?;
        let store = typed::<vault_receive::Payload>(json!({
            "credential": credential,
            "contextId": setup.context,
        }))
        .map_err(internal)?;
        let answer = ask(holder, VAULT_RECEIVE, store, SIGN_TIMEOUT).await?;
        stored.push(
            read::<vault_receive::Response>("vault/credentials/receive", answer)?
                .id
                .to_string(),
        );
    }
    let authority_id = stored.pop().unwrap_or_default();
    let membership_id = stored.pop().unwrap_or_default();
    Ok((membership_id, authority_id))
}

// ─── vtc/rooms/community/{list,get} ──────────────────────────────────────

async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    shape: Shape,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        return reject;
    }
    // `(cursor, limit, tag)`; 0.1 has no `tag`.
    let parsed = match shape {
        Shape::V0_1 => parse_spec_payload::<list::Payload>(&doc)
            .map(|p| (p.cursor.map(|c| c.to_string()), p.limit, None)),
        Shape::V0_2 => parse_spec_payload::<list_v0_2::Payload>(&doc).map(|p| {
            (
                p.cursor.map(|c| c.to_string()),
                p.limit,
                p.tag.map(|t| t.to_string()),
            )
        }),
    };
    let (cursor, limit, tag) = match parsed {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let rooms = match state.community_rooms.rooms().await {
        // 0.2 item 4: only the rooms carrying `tag`, exact strings, paged within the filter.
        Ok(r) => r
            .into_iter()
            .filter(|r| tag.as_ref().is_none_or(|t| r.tags.contains(t)))
            .collect::<Vec<_>>(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let (rooms, next) = match page(
        &doc,
        rooms,
        |r| r.room_id.clone(),
        ROOMS_CURSOR,
        cursor.as_deref(),
        limit,
    ) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let listed: Vec<String> = rooms.iter().map(|r| r.room_id.clone()).collect();
    let mut items = Vec::with_capacity(rooms.len());
    for room in &rooms {
        match community_room(state, room, shape).await {
            Ok(v) => items.push(v),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let mut body = json!({ "items": items });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    // Off until the operator turns it on: the console reads this to say what to add.
    let mut setting = if state.config.read().await.rooms.community.is_none() {
        json!({
            "enabled": false,
            "configure": "[rooms.community]\ncontext = \"<the context at the community's VTA the rooms' keys are minted in>\"",
        })
    } else {
        json!({ "enabled": true })
    };
    // What the community's entry at its VTA must hold, and the `pnm` commands that fix
    // it: here, to a holder of `vtc.rooms.manage`, rather than on a refusal, whose
    // `message` may not carry the VTA's contexts (`rooms::vta_access`).
    if let Some(facts) = vta_access::Facts::read(state).await {
        setting["vtaAccess"] = vta_access::list_ext(&facts);
    }
    body["ext"] = json!({ "org.openvtc": { "communityRooms": setting } });
    // Removals owed on members' departures from the community, in this page's rooms, until
    // the worker completes them (`crate::rooms::departures`).
    let ids: Vec<&str> = rooms.iter().map(|r| r.room_id.as_str()).collect();
    match crate::rooms::departures::ext_for(state, &ids).await {
        Ok(Some(owed)) => body["ext"]["org.openvtc"]["departureRemovals"] = owed,
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // How the renewal of the community's own authority stands, per room
    // (`rooms::community_renewal`): the shared `CommunityRoom` has no member for it.
    match crate::rooms::community_renewal::list_ext(state, &listed).await {
        Ok(Some(renewal)) => body["ext"]["org.openvtc"]["authorityRenewal"] = renewal,
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Whether each room's profile is written into it, pending, or was never written
    // (`rooms::community_profile`).
    match crate::rooms::community_profile::list_ext(state, &listed).await {
        Ok(profiles) => body["ext"]["org.openvtc"]["roomProfile"] = profiles,
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match shape {
        Shape::V0_1 => respond::<list::Response>(&doc, body),
        Shape::V0_2 => respond::<list_v0_2::Response>(&doc, body),
    }
}

async fn handle_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    shape: Shape,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        return reject;
    }
    let parsed = match shape {
        Shape::V0_1 => parse_spec_payload::<get::Payload>(&doc).map(|p| p.room_id.to_string()),
        Shape::V0_2 => parse_spec_payload::<get_v0_2::Payload>(&doc).map(|p| p.room_id.to_string()),
    };
    let room_id = match parsed {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let room = match owned(state, &doc, &room_id, c::GET_NOT_FOUND).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let mut body = match community_room(state, &room, shape).await {
        Ok(room) => json!({ "room": room }),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // How the renewal of the community's own authority stands (`rooms::community_renewal`).
    match crate::rooms::community_renewal::room_ext(state, &room.room_id).await {
        Ok(Some(renewal)) => body["ext"]["org.openvtc"]["authorityRenewal"] = renewal,
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match crate::rooms::community_profile::room_ext(state, &room.room_id).await {
        Ok(profile) => body["ext"]["org.openvtc"]["roomProfile"] = profile,
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Removals owed on members' departures, while the worker drives them.
    match crate::rooms::departures::ext_for(state, &[room.room_id.as_str()]).await {
        Ok(Some(owed)) => body["ext"]["org.openvtc"]["departureRemovals"] = owed,
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match shape {
        Shape::V0_1 => respond::<get::Response>(&doc, body),
        Shape::V0_2 => respond::<get_v0_2::Response>(&doc, body),
    }
}

// ─── vtc/rooms/community/update ──────────────────────────────────────────

/// `vtc/rooms/community/update/0.1` — an administrator renames a room the community owns,
/// or changes its description or tags.
///
/// No operation-bound step-up and no parking: it reaches no key holder, confers nothing
/// and is undone by the same task (the specification's *model this task is designed
/// for*). Proof and `issuedAt` are required, which the spine enforces from the
/// specification, so a replayed earlier update is refused before it gets here.
///
/// The details are the community's own record as the room's owner: written beside the
/// room in [`crate::rooms::community`], never to its host record, its records or its VTA
/// (item 8). Its live hint is the `communityRooms` topic's (`vtc/admin/events/0.4`), not
/// `rooms`', which covers the host's view.
async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    writes_profile: bool,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    // Item 1.
    let actor = match capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    // 0.1 and 0.2 carry the same request; 0.2 also writes the room's profile (items 10-12).
    let parsed = if writes_profile {
        parse_spec_payload::<update_v0_2::Payload>(&doc).map(|p| {
            (
                p.room_id.to_string(),
                p.label.map(|l| l.to_string()),
                p.description.map(|d| d.to_string()),
                p.remove_description == Some(true),
                p.tags
                    .map(|t| tag_set(t.0.into_iter().map(|t| t.to_string()))),
                p.reason.to_string(),
            )
        })
    } else {
        parse_spec_payload::<update::Payload>(&doc).map(|p| {
            (
                p.room_id.to_string(),
                p.label.map(|l| l.to_string()),
                p.description.map(|d| d.to_string()),
                p.remove_description == Some(true),
                p.tags
                    .map(|t| tag_set(t.0.into_iter().map(|t| t.to_string()))),
                p.reason.to_string(),
            )
        })
    };
    let (room_id, new_label, new_description, remove_description, new_tags, reason) = match parsed {
        Ok(p) => p,
        Err(reject) => return reject,
    };

    // Read, compare and write under the record's guard: a renewal moving the authority's
    // expiry at the same moment does not write this change back stale, nor this one its.
    let guard = state.community_rooms.record_lock().await;
    // Item 2: a room the community only hosts is `notFound`, and nothing is kept for it.
    let mut room = match owned(state, &doc, &room_id, c::UPDATE_NOT_FOUND).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let before = room.clone();

    // Item 3: each member given replaces the stored one; an absent one is unchanged.
    if let Some(l) = new_label {
        room.label = l;
    }
    if let Some(d) = new_description {
        room.description = Some(d);
    } else if remove_description {
        room.description = None;
    }
    if let Some(t) = new_tags {
        room.tags = t;
    }
    // Item 4: tags compare as sets — both are kept sorted and unique.
    let before_tags = tag_set(before.tags.iter().cloned());
    let mut details = Vec::new();
    if room.label != before.label {
        details.push(detail_change(
            "label",
            Some(json!(before.label)),
            Some(json!(room.label)),
        ));
    }
    if room.description != before.description {
        details.push(detail_change(
            "description",
            before.description.as_ref().map(|d| json!(d)),
            room.description.as_ref().map(|d| json!(d)),
        ));
    }
    if room.tags != before_tags {
        details.push(detail_change(
            "tags",
            tags_value(&before_tags),
            tags_value(&room.tags),
        ));
    }
    let changed = !details.is_empty();
    // Item 10: only a change to what the profile carries — the label and the description,
    // never the tags — asks for it to be written again.
    let profile_changed = room.label != before.label || room.description != before.description;

    if changed {
        // Item 5.
        room.details_updated_at = Some(rfc3339(now()));
        room.details_updated_by = Some(actor.did.clone());
        if let Err(e) = state.community_rooms.put_room_details(&room).await {
            return app_error_to_reject(&doc, &e);
        }
    } else {
        // Item 4: nothing is written, and the answer is the room as it stands.
        room = before;
    }
    drop(guard);

    if changed {
        // Item 6: one record, with each changed detail's previous and new value.
        let mut row = change("detailsUpdated", &room);
        row.reason = Some(reason.clone());
        row.details = details;
        audit(state, &actor.did, row).await;
        tracing::info!(room = %room_id, by = %actor.did, "community room details changed");
    }

    // 0.2 items 10 and 11: write the profile when the label or description changed, or
    // when the community has never written it (a room made before create 0.3) or an
    // earlier write is still pending; `unchanged` when nothing asked for a write. A failure
    // is `pending`, never a failed update.
    let room_profile = if writes_profile {
        match crate::rooms::community_profile::update_needs_write(state, &room_id, profile_changed)
            .await
        {
            Ok(true) => Some(
                crate::rooms::community_profile::write_now(state, &room, now())
                    .await
                    .as_str(),
            ),
            Ok(false) => Some("unchanged"),
            Err(e) => {
                tracing::warn!(room = %room_id, error = %e,
                    "could not read a community room's profile state; answering pending");
                Some("pending")
            }
        }
    } else {
        None
    };

    match community_room(state, &room, Shape::V0_2).await {
        Ok(v) => match room_profile {
            None => respond::<update::Response>(&doc, json!({ "room": v, "changed": changed })),
            Some(p) => respond::<update_v0_2::Response>(
                &doc,
                json!({ "room": v, "changed": changed, "roomProfile": p }),
            ),
        },
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── vtc/rooms/community/members/* ───────────────────────────────────────

async fn handle_members_add(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let actor = match capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: add::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room_id = checked.room_id.to_string();
    let member = checked.member.to_string();
    let actions: Vec<String> = checked.actions.0.iter().map(|a| a.to_string()).collect();
    let valid_until = rfc3339(checked.valid_until);

    let room = match owned(state, &doc, &room_id, c::ADD_NOT_FOUND).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    // Item 2: a room the community owns is a community resource.
    match crate::member_portal::active_member(state, &member).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return refuse(
                &doc,
                c::ADD_NOT_A_MEMBER,
                format!("`{member}` is not an active member of this community"),
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let Some(holder) = state.community_rooms.key_holder() else {
        return refuse(
            &doc,
            c::ADD_KEY_HOLDER_UNAVAILABLE,
            "this community has no link to the VTA that holds the room's keys",
            None,
        );
    };
    let _guard = state.community_rooms.lock().await;
    // Item 3.
    match state.community_rooms.member(&room_id, &member).await {
        Ok(Some(r)) if r.state != MemberRecord::REMOVED => {
            return refuse(
                &doc,
                c::ADD_ALREADY_MEMBER,
                format!("`{member}` is already {} in this room", r.state),
                None,
            );
        }
        Ok(_) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Admit {member} to the community room “{}”", room.label),
    )
    .await
    {
        return reject;
    }

    // Item 4: three credentials, issued by the room through the community's VTA, the
    // authority granting exactly `actions` until `validUntil`.
    let issued = issue_offer(&holder, &room, &member, &actions, &valid_until).await;
    let credentials = match issued {
        Ok(c) => c,
        Err(HolderError::Unavailable(why)) => {
            return refuse(&doc, c::ADD_KEY_HOLDER_UNAVAILABLE, why, None);
        }
        Err(HolderError::Refused { code, message }) => {
            return refuse_logged(
                state,
                &doc,
                c::ADD_KEY_HOLDER_REFUSED,
                format!("the community's VTA refused: {code} {message}"),
                Some(HolderError::refused_details(&code, &message)),
            )
            .await;
        }
    };

    // Item 5: recorded only now, and the credentials kept for the member alone.
    let record = MemberRecord {
        room_id: room_id.clone(),
        member: member.clone(),
        actions: actions.clone(),
        valid_until,
        state: MemberRecord::OFFERED.into(),
        offered_at: rfc3339(now()),
        admitted_at: None,
        removed_at: None,
        credentials: Some(credentials),
        welcome: None,
        admitted_epoch: None,
        renewal: None,
        sources: Vec::new(),
    };
    if let Err(e) = state.community_rooms.put_member(&record).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);

    let mut row = change("memberOffered", &room);
    row.member = Some(member);
    row.actions = actions;
    row.reason = Some(checked.reason.to_string());
    audit(state, &actor.did, row).await;
    respond::<add::Response>(&doc, json!({ "member": record.wire() }))
}

/// The invitation, membership and authority credentials for `member`.
pub(crate) async fn issue_offer(
    holder: &KeyHolder,
    room: &OwnedRoom,
    member: &str,
    actions: &[String],
    valid_until: &str,
) -> Result<OfferCredentials, HolderError> {
    let internal = |e: AppError| HolderError::Unavailable(e.to_string());
    let common = json!({
        "roomId": room.room_id,
        "signingKeyId": room.signing_key_id,
        "subject": member,
        "validUntil": valid_until,
    });
    let invite = typed::<owner_invite::Payload>(common.clone()).map_err(internal)?;
    let membership = typed::<owner_membership::Payload>(common.clone()).map_err(internal)?;
    let mut authority = common;
    authority["actions"] = json!(actions);
    let authority = typed::<owner_authority::Payload>(authority).map_err(internal)?;

    let invitation = read::<owner_invite::Response>(
        "rooms/owner/invite",
        ask(holder, OWNER_INVITE, invite, SIGN_TIMEOUT).await?,
    )?
    .credential;
    let membership = read::<owner_membership::Response>(
        "rooms/owner/issue-membership",
        ask(holder, OWNER_MEMBERSHIP, membership, SIGN_TIMEOUT).await?,
    )?
    .credential;
    let authority = read::<owner_authority::Response>(
        "rooms/owner/issue-authority",
        ask(holder, OWNER_AUTHORITY, authority, SIGN_TIMEOUT).await?,
    )?
    .credential;
    Ok(OfferCredentials {
        invitation,
        membership,
        authority,
    })
}

/// A renewal of `member`'s admission to `room`: fresh membership and authority
/// credentials, the authority granting exactly `actions` until `valid_until`. No
/// invitation: the member is already in the room (`vtc/rooms/offers/list/0.3` item 5).
pub(crate) async fn issue_renewal(
    holder: &KeyHolder,
    room: &OwnedRoom,
    member: &str,
    actions: &[String],
    valid_until: &str,
) -> Result<(String, String), HolderError> {
    let internal = |e: AppError| HolderError::Unavailable(e.to_string());
    let common = json!({
        "roomId": room.room_id,
        "signingKeyId": room.signing_key_id,
        "subject": member,
        "validUntil": valid_until,
    });
    let membership = typed::<owner_membership::Payload>(common.clone()).map_err(internal)?;
    let mut authority = common;
    authority["actions"] = json!(actions);
    let authority = typed::<owner_authority::Payload>(authority).map_err(internal)?;
    let membership = read::<owner_membership::Response>(
        "rooms/owner/issue-membership",
        ask(holder, OWNER_MEMBERSHIP, membership, SIGN_TIMEOUT).await?,
    )?
    .credential;
    let authority = read::<owner_authority::Response>(
        "rooms/owner/issue-authority",
        ask(holder, OWNER_AUTHORITY, authority, SIGN_TIMEOUT).await?,
    )?
    .credential;
    Ok((membership, authority))
}

async fn handle_members_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: RemoveVersion,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let actor = match capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: remove::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room_id = checked.room_id.to_string();
    let member = checked.member.to_string();
    let reason = checked.reason.to_string();

    let room = match owned(state, &doc, &room_id, c::REMOVE_NOT_FOUND).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let _guard = state.community_rooms.lock().await;
    let mut record = match state.community_rooms.member(&room_id, &member).await {
        Ok(Some(r)) if r.state != MemberRecord::REMOVED => r,
        Ok(_) => {
            return refuse(
                &doc,
                c::REMOVE_NOT_IN_ROOM,
                format!("`{member}` holds neither an admission to this room nor an open offer"),
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    if let Err(reject) = bound_step_up(
        state,
        &actor.did,
        &doc,
        &format!("Remove {member} from the community room “{}”", room.label),
    )
    .await
    {
        return reject;
    }

    // Item 2. At 0.1 an admitted member of a sealed room leaves the group and the room
    // advances. At 0.2 (trust-tasks-tf #804) the member is withdrawn at the host too on
    // `open` and `attributed` rooms, and an open offer's credentials with them
    // ([`crate::rooms::departures::remove_member`]). Either way, before anything is
    // recorded here.
    let withdrawn = record.state == MemberRecord::OFFERED;
    let mut epoch = None;
    let mut revocation: Option<(Value, String)> = None;
    let asks_vta = match version {
        RemoveVersion::V0_1 => !withdrawn && sealed(&room),
        RemoveVersion::V0_2 => !(withdrawn && room.visibility == "private"),
    };
    if asks_vta {
        let Some(holder) = state.community_rooms.key_holder() else {
            return refuse(
                &doc,
                c::REMOVE_KEY_HOLDER_UNAVAILABLE,
                "this community has no link to the VTA that holds the room's keys",
                None,
            );
        };
        let community_did = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_default();
        let outcome = match version {
            RemoveVersion::V0_1 => crate::rooms::departures::remove_from_group(
                &holder,
                &room_id,
                &community_did,
                &member,
                &reason,
            )
            .await
            .map(|epoch| crate::rooms::departures::Removed {
                epoch,
                revocation: None,
            }),
            RemoveVersion::V0_2 => {
                crate::rooms::departures::remove_member(
                    &holder,
                    &room,
                    &community_did,
                    &member,
                    withdrawn,
                    &reason,
                )
                .await
            }
        };
        match outcome {
            Ok(r) => {
                epoch = r.epoch;
                revocation = r.revocation;
            }
            // Not answered, or the host — this community — did not answer the VTA: the
            // outcome is unknown, and the VTA settles it on the next request.
            Err(HolderError::Unavailable(why)) => {
                return refuse(&doc, c::REMOVE_KEY_HOLDER_UNAVAILABLE, why, None);
            }
            Err(HolderError::Refused { code, message }) => {
                // `rooms/owner/group/remove/0.3` item 8.2: an earlier removal from this room
                // did not take effect, and nothing of this one was done. The administrator
                // has two things to do, and the VTA's message names the member.
                let said = if code == EARLIER_REMOVAL_REFUSED {
                    format!(
                        "nothing was done: the community's VTA found an earlier removal from \
                         this room still pending, and the room's host refused its revocation \
                         list when the VTA delivered it again, so that earlier removal did not \
                         take effect ({message}). Repeat this removal; then remove the member \
                         that message names again if that is still wanted"
                    )
                } else {
                    format!("the community's VTA refused: {code} {message}")
                };
                return refuse_logged(
                    state,
                    &doc,
                    c::REMOVE_KEY_HOLDER_REFUSED,
                    said,
                    Some(HolderError::refused_details(&code, &message)),
                )
                .await;
            }
        }
    }

    // Item 3: an open offer is withdrawn, so it is never listed or accepted again.
    record.state = MemberRecord::REMOVED.into();
    record.removed_at = Some(rfc3339(now()));
    record.credentials = None;
    record.renewal = None;
    record.sources.clear();
    record.welcome = None;
    // A removal owed on the member's departure from the community, if one is, is settled
    // by this one (`crate::rooms::departures`).
    if let Err(e) = state.community_rooms.settle_removal(&record).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);

    let mut row = change(
        if withdrawn {
            "offerWithdrawn"
        } else {
            "memberRemoved"
        },
        &room,
    );
    let notice = match version {
        RemoveVersion::V0_1 => REMOVAL_NOTICE,
        RemoveVersion::V0_2 => crate::rooms::departures::removal_notice(revocation.is_some()),
    };
    row.member = Some(member);
    row.epoch = epoch;
    row.reason = Some(reason);
    if !withdrawn || revocation.is_some() {
        row.note = Some(notice.into());
    }
    audit(state, &actor.did, row).await;

    // Item 4: the structured members say what removal did — at 0.2 `revocation` and
    // `revokedAt` where the host refuses the member's credentials from then on; the notice
    // beside them in `ext` is a courtesy a caller must not depend on (#796).
    let mut body = json!({
        "member": record.wire(),
        "ext": { "org.openvtc": { "notice": notice } },
    });
    if let Some((head, revoked_at)) = revocation {
        body["revocation"] = head;
        body["revokedAt"] = json!(revoked_at);
    }
    if let Some(e) = epoch.filter(|e| *e >= 2 && !withdrawn) {
        body["epoch"] = json!(e);
    }
    match version {
        RemoveVersion::V0_1 => respond::<remove::Response>(&doc, body),
        RemoveVersion::V0_2 => respond::<remove_v0_2::Response>(&doc, body),
    }
}

async fn handle_members_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        return reject;
    }
    let checked: members_list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room_id = checked.room_id.to_string();
    if let Err(reject) = owned(state, &doc, &room_id, c::MEMBERS_LIST_NOT_FOUND).await {
        return reject;
    }
    let want = checked.state.map(|s| s.to_string());
    let members = match state.community_rooms.members(&room_id).await {
        Ok(m) => m
            .into_iter()
            .filter(|m| want.as_deref().is_none_or(|s| m.state == s))
            .collect::<Vec<_>>(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let (members, next) = match page(
        &doc,
        members,
        |m| m.member.clone(),
        MEMBERS_CURSOR,
        checked.cursor.as_ref().map(|c| c.as_str()),
        checked.limit,
    ) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let mut body = json!({ "items": members.iter().map(MemberRecord::wire).collect::<Vec<_>>() });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    // A member whose removal is owed on their departure is still listed as they were until
    // it completes; this says which, and why it has not yet.
    match crate::rooms::departures::ext_for(state, &[room_id.as_str()]).await {
        Ok(Some(owed)) => body["ext"]["org.openvtc"]["departureRemovals"] = owed,
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    respond::<members_list::Response>(&doc, body)
}

// ─── vtc/rooms/offers/* — the member's half ──────────────────────────────

/// The proven signer, when they are an active member now — the only party an offer's
/// tasks answer.
async fn active_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    not_a_member: &str,
) -> Result<String, TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.clone() else {
        return Err(reject_with(doc, RejectReason::ProofRequired));
    };
    match crate::member_portal::active_member(state, &signer).await {
        Ok(Some(_)) => Ok(signer),
        Ok(None) => Err(refuse(
            doc,
            not_a_member,
            "the signer is not an active member of this community",
            None,
        )),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

async fn handle_offers_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    shape: OffersShape,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let signer = match active_signer(state, ctx, &doc, c::OFFERS_LIST_NOT_A_MEMBER).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let parsed = match shape {
        OffersShape::V0_1 => parse_spec_payload::<offers_list::Payload>(&doc)
            .map(|p| (p.cursor.map(|c| c.to_string()), p.limit)),
        OffersShape::V0_2 => parse_spec_payload::<offers_list_v0_2::Payload>(&doc)
            .map(|p| (p.cursor.map(|c| c.to_string()), p.limit)),
        OffersShape::V0_3 => parse_spec_payload::<offers_list_v0_3::Payload>(&doc)
            .map(|p| (p.cursor.map(|c| c.to_string()), p.limit)),
    };
    let (cursor, limit) = match parsed {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let host = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();
    let at = now();
    // Item 1: the signer's own, whatever the request carries. Item 3: never a withdrawn
    // one; an accepted one only while a repeat can be answered.
    let all = match state.community_rooms.records_of(&signer).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // 0.3 item 6: the latest renewal of each admission the member holds, until
    // what it renews expires — on the first page only, in full.
    let mut renewals = Vec::new();
    if shape == OffersShape::V0_3 && cursor.is_none() {
        for r in all.iter().filter(|r| r.state == MemberRecord::ADMITTED) {
            let Some(renewal) = &r.renewal else {
                continue;
            };
            if chrono::DateTime::parse_from_rfc3339(&renewal.renews)
                .is_ok_and(|t| t.with_timezone(&Utc) <= at)
            {
                continue;
            }
            let room = match state.community_rooms.room(&r.room_id).await {
                Ok(Some(room)) => room,
                Ok(None) => continue,
                Err(e) => return app_error_to_reject(&doc, &e),
            };
            let mut item = json!({
                "roomId": r.room_id,
                "host": host,
                "label": room.label,
                "visibility": room.visibility,
                "actions": r.actions,
                "validUntil": renewal.valid_until,
                "renews": renewal.renews,
                "issuedAt": renewal.issued_at,
                "credentials": {
                    "membership": renewal.membership,
                    "authority": renewal.authority,
                },
            });
            if let Some(d) = &room.description {
                item["description"] = json!(d);
            }
            renewals.push(item);
        }
    }
    let records = all
        .into_iter()
        .filter(|r| {
            r.credentials.is_some() && (r.state == MemberRecord::OFFERED || r.welcome_kept(at))
        })
        .collect::<Vec<_>>();
    let (records, next) = match page(
        &doc,
        records,
        |r| r.room_id.clone(),
        OFFERS_CURSOR,
        cursor.as_deref(),
        limit,
    ) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let mut items = Vec::with_capacity(records.len());
    for r in &records {
        let room = match state.community_rooms.room(&r.room_id).await {
            Ok(Some(room)) => room,
            Ok(None) => continue,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let Some(credentials) = &r.credentials else {
            continue;
        };
        // The room's details as they stand now, not as they stood when it was offered.
        let mut item = json!({
            "roomId": r.room_id,
            "host": host,
            "label": room.label,
            "visibility": room.visibility,
            "actions": r.actions,
            "validUntil": r.valid_until,
            "offeredAt": r.offered_at,
            "state": if r.state == MemberRecord::OFFERED { "open" } else { "accepted" },
            "credentials": credentials,
        });
        // 0.2 item 4: the description beside the label, and never the tags or anything
        // else of the administrators' tracking.
        if shape != OffersShape::V0_1
            && let Some(d) = &room.description
        {
            item["description"] = json!(d);
        }
        items.push(item);
    }
    let mut body = json!({ "items": items });
    if !renewals.is_empty() {
        body["renewals"] = json!(renewals);
    }
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    match shape {
        OffersShape::V0_1 => respond::<offers_list::Response>(&doc, body),
        OffersShape::V0_2 => respond::<offers_list_v0_2::Response>(&doc, body),
        OffersShape::V0_3 => respond::<offers_list_v0_3::Response>(&doc, body),
    }
}

/// `vtc/rooms/memberships/list/0.1`: the community's own record of the signer's
/// admissions to the rooms it owns, in every state, so that every surface the member uses
/// — the member portal through their wallet, `pnm`, OpenVTC — shows the same rooms in the
/// same state. The same record `offers/accept` writes (item 4), never a credential.
async fn handle_memberships_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let signer = match active_signer(state, ctx, &doc, c::MEMBERSHIPS_LIST_NOT_A_MEMBER).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let checked: memberships_list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let host = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();
    let at = now();
    // Items 1 and 3: the signer's own, in every state, but never an offer withdrawn before
    // it was accepted — recorded as `removed` with no admission.
    let records = match state.community_rooms.records_of(&signer).await {
        Ok(r) => r
            .into_iter()
            .filter(|r| !(r.state == MemberRecord::REMOVED && r.admitted_at.is_none()))
            .collect::<Vec<_>>(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 7: `records_of` is ordered by room, and the cursor names the last room.
    let (records, next) = match page(
        &doc,
        records,
        |r| r.room_id.clone(),
        MEMBERSHIPS_CURSOR,
        checked.cursor.as_ref().map(|c| c.as_str()),
        checked.limit,
    ) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let mut items = Vec::with_capacity(records.len());
    for r in &records {
        let room = match state.community_rooms.room(&r.room_id).await {
            Ok(Some(room)) => room,
            Ok(None) => continue,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        items.push(membership(&host, &room, r, at));
    }
    let mut body = json!({ "items": items });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    respond::<memberships_list::Response>(&doc, body)
}

/// The `RoomMembership` of `vtc/_shared/0.1/community-room` for one record, at `at`.
fn membership(host: &str, room: &OwnedRoom, r: &MemberRecord, at: DateTime<Utc>) -> Value {
    let mut v = json!({
        "roomId": r.room_id,
        "host": host,
        "label": room.label,
        "visibility": room.visibility,
        "actions": r.actions,
        "validUntil": r.valid_until,
        "state": r.state,
        "offeredAt": r.offered_at,
    });
    if let Some(a) = &r.admitted_at {
        v["admittedAt"] = json!(a);
    }
    if let Some(a) = &r.removed_at {
        v["removedAt"] = json!(a);
    }
    // Item 5: exactly while the Welcome of a sealed-tier admission is kept.
    if let Some(until) = repeat_accept_until(room, r, at) {
        v["repeatAcceptUntil"] = json!(rfc3339(until));
    }
    v
}

/// Until when a repeated accept is answered with the kept Welcome, while it still is.
fn repeat_accept_until(
    room: &OwnedRoom,
    r: &MemberRecord,
    at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !sealed(room) || r.welcome.is_none() || !r.welcome_kept(at) {
        return None;
    }
    let admitted = DateTime::parse_from_rfc3339(r.admitted_at.as_deref()?).ok()?;
    Some(admitted.with_timezone(&Utc) + crate::rooms::community::WELCOME_KEPT)
}

async fn handle_offers_accept(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let signer = match active_signer(state, ctx, &doc, c::ACCEPT_NOT_A_MEMBER).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let checked: accept::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room_id = checked.room_id.to_string();
    let key_package = checked.key_package.as_ref().map(|k| k.to_string());
    let not_found = || {
        refuse(
            &doc,
            c::ACCEPT_NOT_FOUND,
            "no open or recently accepted offer to this room is addressed to you",
            None,
        )
    };
    let room = match state.community_rooms.room(&room_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    let _guard = state.community_rooms.lock().await;
    // Item 1: an offer addressed to the proven signer, and to nobody else.
    let mut record = match state.community_rooms.member(&room_id, &signer).await {
        Ok(Some(r)) if r.state != MemberRecord::REMOVED => r,
        Ok(_) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 2.
    match (sealed(&room), &key_package) {
        (true, None) => {
            return refuse(
                &doc,
                c::ACCEPT_KEY_PACKAGE_REQUIRED,
                "this room is sealed: send the KeyPackage your key holder minted against the \
                 offer's invitation (rooms/keys/key-package)",
                None,
            );
        }
        (false, Some(_)) => {
            return refuse(
                &doc,
                c::ACCEPT_KEY_PACKAGE_NOT_EXPECTED,
                "this room is open and has no group: accept without a KeyPackage",
                None,
            );
        }
        _ => {}
    }

    let at = now();
    // Item 4: a repeat.
    if record.state == MemberRecord::ADMITTED {
        return match (sealed(&room), &record.welcome, &key_package) {
            (false, _, _) => accepted(&doc, &room_id, record.admitted_epoch.unwrap_or(1), None),
            (true, Some(w), Some(kp))
                if record.welcome_kept(at) && w.key_package_digest == key_package_digest(kp) =>
            {
                accepted(&doc, &room_id, w.epoch, Some(w))
            }
            _ => refuse(
                &doc,
                c::ACCEPT_ALREADY_ACCEPTED,
                "this offer was already accepted, with another KeyPackage or too long ago for \
                 its Welcome to be kept: ask the community to remove and re-admit you",
                None,
            ),
        };
    }

    if DateTime::parse_from_rfc3339(&record.valid_until).is_ok_and(|v| v.with_timezone(&Utc) <= at)
    {
        return refuse(
            &doc,
            c::ACCEPT_OFFER_EXPIRED,
            format!("the offer expired at {}", record.valid_until),
            None,
        );
    }

    let mut welcome = None;
    let epoch = if let Some(kp) = &key_package {
        // Item 3: on a sealed tier, the VTA adds the member to the group — the room
        // advancing at its host, this community — before anything is recorded here.
        let Some(holder) = state.community_rooms.key_holder() else {
            return refuse(
                &doc,
                c::ACCEPT_ADMISSION_PENDING,
                "the community's VTA cannot be reached now; retry the same request",
                None,
            );
        };
        let host = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_default();
        let request = match typed::<owner_add::Payload>(json!({
            "roomId": room_id,
            "host": host,
            "member": signer,
            "keyPackage": kp,
        })) {
            Ok(r) => r,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        // 0.3 first, then 0.2, whose answer to a repeat of an admission whose reply was
        // lost is its Welcome (item 8). A VTA that does not serve a version never routed the
        // ask, so asking again at the one before — which takes the same request — is not a
        // second admission.
        let mut versions = [OWNER_GROUP_ADD, OWNER_GROUP_ADD_V0_2, OWNER_GROUP_ADD_V0_1].iter();
        let asked = loop {
            let Some(uri) = versions.next() else {
                unreachable!("at least one version is asked");
            };
            let answer = ask(&holder, uri, request.clone(), ADVANCE_TIMEOUT).await;
            let unserved = matches!(&answer, Err(HolderError::Refused { code, .. })
                if matches!(code.as_str(), "unsupportedType" | "unsupportedVersion"));
            if !unserved || versions.len() == 0 {
                break answer;
            }
        };
        match asked {
            Ok(answer) => match read::<owner_add::Response>("rooms/owner/group/add", answer) {
                Ok(r) => {
                    let epoch = u64::try_from(r.epoch).unwrap_or(1);
                    welcome = Some(KeptWelcome {
                        key_package_digest: key_package_digest(kp),
                        welcome: r.welcome.to_string(),
                        ratchet_tree: r.ratchet_tree.map(|t| t.to_string()),
                        epoch,
                    });
                    epoch
                }
                Err(HolderError::Unavailable(why) | HolderError::Refused { message: why, .. }) => {
                    return refuse(&doc, c::ACCEPT_ADMISSION_PENDING, why, None);
                }
            },
            Err(HolderError::Unavailable(why)) => {
                return refuse(&doc, c::ACCEPT_ADMISSION_PENDING, why, None);
            }
            Err(HolderError::Refused { code, message })
                if code == owner_add::error_codes::HOST_UNREACHABLE.code =>
            {
                return refuse(&doc, c::ACCEPT_ADMISSION_PENDING, message, None);
            }
            Err(HolderError::Refused { code, message })
                if code == owner_add::error_codes::KEY_PACKAGE_INVALID.code =>
            {
                return refuse(&doc, c::ACCEPT_KEY_PACKAGE_INVALID, message, None);
            }
            // The member already has a leaf, and the VTA cannot answer this as a repeat:
            // another KeyPackage, an admission whose Welcome the VTA no longer keeps (it
            // keeps it until its next advance of the room or 24 hours —
            // `rooms/owner/group/add/0.2` item 8), or a VTA serving only 0.1, which keeps
            // none. They are in the group with no Welcome anyone can give them: that is
            // `alreadyAccepted`, and the record says admitted so a removal can find them.
            Err(HolderError::Refused { code, .. })
                if code == owner_add::error_codes::ALREADY_MEMBER.code =>
            {
                record.state = MemberRecord::ADMITTED.into();
                record.admitted_at = Some(rfc3339(at));
                if let Err(e) = state.community_rooms.put_member(&record).await {
                    return app_error_to_reject(&doc, &e);
                }
                return refuse(
                    &doc,
                    c::ACCEPT_ALREADY_ACCEPTED,
                    "you are already in this room's group, and the Welcome that admitted you is \
                     not kept here: ask the community to remove and re-admit you",
                    None,
                );
            }
            // `rooms/owner/group/add/0.3` item 6.1: the VTA was still settling an earlier
            // removal from this room, the host refused its revocation list on redelivery, and
            // nothing of this admission was done. That earlier removal is no longer pending,
            // so the same acceptance now proceeds. The VTA's message names the member that
            // removal concerned: the administrators are told, the accepting member is not.
            Err(HolderError::Refused { code, message }) if code == ADD_EARLIER_REMOVAL_REFUSED => {
                tracing::warn!(
                    room = %room_id, vta_said = %message,
                    "an earlier removal from a community room did not take effect: the room's \
                     host refused its revocation list when the community's VTA delivered it \
                     again. Remove that member again (`cnm rooms members remove`) if that is \
                     still wanted"
                );
                return refuse_logged(
                    state,
                    &doc,
                    c::ACCEPT_KEY_HOLDER_REFUSED,
                    "nothing was done: the community's VTA first settled an earlier change to \
                     this room, which did not take effect. Your acceptance can now proceed: \
                     send the same request again"
                        .to_string(),
                    Some(HolderError::refused_details(
                        &code,
                        "an earlier removal from this room did not take effect; nothing of this \
                         admission was done",
                    )),
                )
                .await;
            }
            Err(HolderError::Refused { code, message }) => {
                return refuse_logged(
                    state,
                    &doc,
                    c::ACCEPT_KEY_HOLDER_REFUSED,
                    format!("the community's VTA refused: {code} {message}"),
                    Some(HolderError::refused_details(&code, &message)),
                )
                .await;
            }
        }
    } else {
        match vti_rooms::storage::get_room(&state.rooms_ks, &room_id).await {
            Ok(r) => u64::from(r.epoch),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    };

    record.state = MemberRecord::ADMITTED.into();
    record.admitted_at = Some(rfc3339(at));
    record.admitted_epoch = Some(epoch);
    record.welcome = welcome.clone();
    if let Err(e) = state.community_rooms.put_member(&record).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);

    // Item 5: never the Welcome or the KeyPackage.
    let mut row = change("memberAdmitted", &room);
    row.member = Some(signer.clone());
    row.epoch = Some(epoch);
    audit(state, &signer, row).await;
    accepted(&doc, &room_id, epoch, welcome.as_ref())
}

fn accepted(
    doc: &TrustTask<Value>,
    room_id: &str,
    epoch: u64,
    welcome: Option<&KeptWelcome>,
) -> TrustTaskOutcome {
    let mut body = json!({ "roomId": room_id, "state": "admitted", "epoch": epoch.max(1) });
    if let Some(w) = welcome {
        body["welcome"] = json!(w.welcome);
        if let Some(t) = &w.ratchet_tree {
            body["ratchetTree"] = json!(t);
        }
    }
    respond::<accept::Response>(doc, body)
}
