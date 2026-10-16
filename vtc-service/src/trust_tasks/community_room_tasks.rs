//! Rooms the community itself owns — `vtc/rooms/community/{create,list,get}/0.1`,
//! `vtc/rooms/community/members/{add,remove,list}/0.1` for its administrators, and
//! `vtc/rooms/offers/{list,accept}/0.1` for its members
//! (`docs/05-design-notes/data-rooms-files.md` §8.4; [`crate::rooms::community`]).
//!
//! # Authority
//!
//! | task | signed by | authority (read at execution time) |
//! |---|---|---|
//! | `community/*`, `community/members/*` | an administrator | `vtc.rooms.manage` on the signer's live entry (or a console key's administrator's) |
//! | `offers/list`, `offers/accept` | a member | being the member the offer names, and an **active** member now |
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
        add::v0_1 as owner_add_v0_1, add::v0_2 as owner_add, create::v0_1 as owner_group_create,
        remove::v0_1 as owner_remove,
    },
    invite::v0_1 as owner_invite,
    issue_authority::v0_2 as owner_authority,
    issue_membership::v0_1 as owner_membership,
};
use trust_tasks_rs::specs::vault::credentials::receive::v0_1 as vault_receive;
use trust_tasks_rs::specs::vtc::rooms::community::{
    create::v0_1 as create, get::v0_1 as get, list::v0_1 as list, members::add::v0_1 as add,
    members::list::v0_1 as members_list, members::remove::v0_1 as remove,
};
use trust_tasks_rs::specs::vtc::rooms::offers::{
    accept::v0_1 as accept, list::v0_1 as offers_list,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, CommunityRoomChangedData};
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
use crate::server::AppState;

pub(crate) const CREATE_TYPE: &str = <create::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const GET_TYPE: &str = <get::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_ADD_TYPE: &str = <add::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_REMOVE_TYPE: &str = <remove::Payload as Payload>::TYPE_URI;
pub(crate) const MEMBERS_LIST_TYPE: &str = <members_list::Payload as Payload>::TYPE_URI;
pub(crate) const OFFERS_LIST_TYPE: &str = <offers_list::Payload as Payload>::TYPE_URI;
pub(crate) const OFFERS_ACCEPT_TYPE: &str = <accept::Payload as Payload>::TYPE_URI;

/// Every URI [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    CREATE_TYPE,
    LIST_TYPE,
    GET_TYPE,
    MEMBERS_ADD_TYPE,
    MEMBERS_REMOVE_TYPE,
    MEMBERS_LIST_TYPE,
    OFFERS_LIST_TYPE,
    OFFERS_ACCEPT_TYPE,
];

const OWNER_GROUP_CREATE: &str = <owner_group_create::Payload as Payload>::TYPE_URI;
const OWNER_GROUP_ADD: &str = <owner_add::Payload as Payload>::TYPE_URI;
/// For a VTA that does not serve `rooms/owner/group/add/0.2`: same request, same response,
/// but a repeated admission is refused `alreadyMember` rather than answered (0.2 item 8).
const OWNER_GROUP_ADD_V0_1: &str = <owner_add_v0_1::Payload as Payload>::TYPE_URI;
const OWNER_GROUP_REMOVE: &str = <owner_remove::Payload as Payload>::TYPE_URI;
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

/// What removal does not do — said in the audit row, and in the answer's `ext` only as a
/// courtesy. `vtc/rooms/community/members/remove` item 4 (clarified in place,
/// trust-tasks-tf #796) requires only that neither represent a removal as recalling what
/// was read, re-sealing what was written or revoking the authority credential: the answer
/// says what removal did in its structured members (`member.state`, `member.validUntil`,
/// `epoch`), and a caller must not depend on this notice.
const REMOVAL_NOTICE: &str = "Removal ends access to what is written from now on. It recalls \
     nothing the member already read, and their authority credential is not revoked: a host \
     honours it until it expires, though on a sealed room it opens nothing written after this.";

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CREATE_TYPE => handle_create(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        GET_TYPE => handle_get(state, ctx, doc).await,
        MEMBERS_ADD_TYPE => handle_members_add(state, ctx, doc).await,
        MEMBERS_REMOVE_TYPE => handle_members_remove(state, ctx, doc).await,
        MEMBERS_LIST_TYPE => handle_members_list(state, ctx, doc).await,
        OFFERS_LIST_TYPE => handle_offers_list(state, ctx, doc).await,
        OFFERS_ACCEPT_TYPE => handle_offers_accept(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── shared ──────────────────────────────────────────────────────────────

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
async fn bound_step_up(
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

async fn audit(state: &AppState, actor: &str, data: CommunityRoomChangedData) {
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

fn change(event: &str, room: &OwnedRoom) -> CommunityRoomChangedData {
    CommunityRoomChangedData {
        event: event.to_string(),
        room_id: room.room_id.clone(),
        visibility: room.visibility.clone(),
        member: None,
        actions: Vec::new(),
        epoch: None,
        note: None,
        reason: None,
    }
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

/// The `CommunityRoom` of `vtc/_shared/0.1/community-room`.
async fn community_room(state: &AppState, room: &OwnedRoom) -> Result<Value, AppError> {
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
}

async fn setup(state: &AppState) -> Result<Setup, String> {
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
    let publish = match (&community.webvh_server, &config.public_url) {
        (Some(server), _) => Publish::Server(server.clone()),
        (None, Some(url)) => Publish::Served {
            public_url: url.trim_end_matches('/').to_string(),
        },
        (None, None) => {
            return Err(
                "a room's identity is served from this community's public URL unless \
                        `[rooms.community] webvh_server` names a hosting server at the VTA: set \
                        `public_url`, or `webvh_server`"
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

async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let actor = match capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: create::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let label = checked.label.to_string();
    let visibility: vti_rooms::Visibility =
        match serde_json::from_value(json!(checked.visibility.to_string())) {
            Ok(v) => v,
            Err(e) => return malformed(&doc, format!("`visibility`: {e}")),
        };
    let retention_policy = match checked.retention_policy {
        Some(create::RetentionPolicy::FromJoin) => vti_rooms::RetentionPolicy::FromJoin,
        _ => vti_rooms::RetentionPolicy::Chained,
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
        Err(why) => return refuse(&doc, c::CREATE_NO_KEY_HOLDER, why, None),
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
    let (room_id, signing_key_id, did_path) =
        match mint_and_equip(&setup, &label, visibility, authority_until, state).await {
            Ok(v) => v,
            Err(CreateFailure::Holder(HolderError::Unavailable(why), minted)) => {
                let details = minted.map(|d| json!({ "roomId": d }));
                return refuse(&doc, c::CREATE_KEY_HOLDER_UNAVAILABLE, why, details);
            }
            Err(CreateFailure::Holder(HolderError::Refused { code, message }, _)) => {
                return refuse(
                    &doc,
                    c::CREATE_KEY_HOLDER_REFUSED,
                    format!("the community's VTA refused: {code} {message}"),
                    Some(HolderError::refused_details(&code, &message)),
                );
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
    let owned = OwnedRoom {
        room_id: room_id.clone(),
        label: label.clone(),
        visibility: checked.visibility.to_string(),
        signing_key_id,
        created_by: actor.did.clone(),
        created_at: rfc3339(now()),
        owner_authority_valid_until: rfc3339(authority_until),
        did_path,
    };
    if let Err(e) = state.community_rooms.put_room(&owned).await {
        return app_error_to_reject(&doc, &e);
    }

    let mut row = change("created", &owned);
    row.reason = Some(checked.reason.to_string());
    audit(state, &actor.did, row).await;
    tracing::info!(room = %room_id, by = %actor.did, "community room created");

    match community_room(state, &owned).await {
        Ok(room) => respond::<create::Response>(&doc, json!({ "room": room })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Steps 1–3 of `vtc/rooms/community/create`, all at the community's VTA: mint the room's
/// DID, found its group on a sealed tier, and issue and store the community's own
/// membership and `admin` authority. Answers the room's DID, its signing key, and the
/// path its log is served under when this service serves it.
async fn mint_and_equip(
    setup: &Setup,
    label: &str,
    visibility: vti_rooms::Visibility,
    authority_until: DateTime<Utc>,
    state: &AppState,
) -> Result<(String, String, Option<String>), CreateFailure> {
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
    let mint = typed::<vta_sdk::protocols::did_management::create::CreateDidWebvhBody>(mint)
        .map_err(local)?;
    let minted = ask(
        holder,
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_1,
        mint,
        SIGN_TIMEOUT,
    )
    .await
    .map_err(|e| CreateFailure::Holder(e, None))?;
    let minted: vta_sdk::protocols::did_management::create::CreateDidWebvhResultBody =
        read("webvh/dids/create", minted).map_err(|e| CreateFailure::Holder(e, None))?;
    let room_id = minted.did.clone();
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
            .put_did_log(path, &room_id, log)
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
    if let Err(e) = rest {
        // Nothing is stored for a room that failed; a log served for it would name an
        // identity nobody uses.
        if let Some(path) = &did_path {
            let _ = state.community_rooms.remove_did_log(path).await;
        }
        return Err(CreateFailure::Holder(e, Some(room_id)));
    }
    Ok((room_id, signing_key_id, did_path))
}

/// Steps 2 and 3.
async fn equip(
    setup: &Setup,
    room_id: &str,
    signing_key_id: &str,
    visibility: vti_rooms::Visibility,
    authority_until: DateTime<Utc>,
) -> Result<(), HolderError> {
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
        read::<vault_receive::Response>("vault/credentials/receive", answer)?;
    }
    Ok(())
}

// ─── vtc/rooms/community/{list,get} ──────────────────────────────────────

async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        return reject;
    }
    let checked: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let rooms = match state.community_rooms.rooms().await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let (rooms, next) = match page(
        &doc,
        rooms,
        |r| r.room_id.clone(),
        ROOMS_CURSOR,
        checked.cursor.as_ref().map(|c| c.as_str()),
        checked.limit,
    ) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let mut items = Vec::with_capacity(rooms.len());
    for room in &rooms {
        match community_room(state, room).await {
            Ok(v) => items.push(v),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let mut body = json!({ "items": items });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    // Off until the operator turns it on: the console reads this to say what to add.
    if state.config.read().await.rooms.community.is_none() {
        body["ext"] = json!({ "org.openvtc": { "communityRooms": {
            "enabled": false,
            "configure": "[rooms.community]\ncontext = \"<the context at the community's VTA the rooms' keys are minted in>\"",
        } } });
    }
    respond::<list::Response>(&doc, body)
}

async fn handle_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::RoomsManage, None).await {
        return reject;
    }
    let checked: get::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room = match owned(state, &doc, checked.room_id.as_str(), c::GET_NOT_FOUND).await {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    match community_room(state, &room).await {
        Ok(room) => respond::<get::Response>(&doc, json!({ "room": room })),
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
            return refuse(
                &doc,
                c::ADD_KEY_HOLDER_REFUSED,
                format!("the community's VTA refused: {code} {message}"),
                Some(HolderError::refused_details(&code, &message)),
            );
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
async fn issue_offer(
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

async fn handle_members_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
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

    // Item 2: an admitted member of a sealed room leaves the group, and the room advances
    // to an epoch sealed to everyone else, before anything is recorded here.
    let withdrawn = record.state == MemberRecord::OFFERED;
    let mut epoch = None;
    if !withdrawn && sealed(&room) {
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
        let request = match typed::<owner_remove::Payload>(json!({
            "roomId": room_id,
            "host": community_did,
            "member": member,
            "reason": reason,
        })) {
            Ok(r) => r,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        match ask(&holder, OWNER_GROUP_REMOVE, request, ADVANCE_TIMEOUT).await {
            Ok(answer) => {
                match read::<owner_remove::Response>("rooms/owner/group/remove", answer) {
                    Ok(r) => epoch = u64::try_from(r.epoch).ok(),
                    Err(
                        HolderError::Unavailable(why) | HolderError::Refused { message: why, .. },
                    ) => {
                        return refuse(&doc, c::REMOVE_KEY_HOLDER_UNAVAILABLE, why, None);
                    }
                }
            }
            // The member holds no leaf: nothing to advance past, and recording the
            // removal says what is true.
            Err(HolderError::Refused { code, .. })
                if code == owner_remove::error_codes::NOT_MEMBER.code => {}
            // The host — this community — did not answer the VTA: the outcome is unknown,
            // and the VTA settles it on the next request.
            Err(HolderError::Refused { code, message })
                if code == owner_remove::error_codes::HOST_UNREACHABLE.code =>
            {
                return refuse(&doc, c::REMOVE_KEY_HOLDER_UNAVAILABLE, message, None);
            }
            Err(HolderError::Unavailable(why)) => {
                return refuse(&doc, c::REMOVE_KEY_HOLDER_UNAVAILABLE, why, None);
            }
            Err(HolderError::Refused { code, message }) => {
                return refuse(
                    &doc,
                    c::REMOVE_KEY_HOLDER_REFUSED,
                    format!("the community's VTA refused: {code} {message}"),
                    Some(HolderError::refused_details(&code, &message)),
                );
            }
        }
    }

    // Item 3: an open offer is withdrawn, so it is never listed or accepted again.
    record.state = MemberRecord::REMOVED.into();
    record.removed_at = Some(rfc3339(now()));
    record.credentials = None;
    record.welcome = None;
    if let Err(e) = state.community_rooms.put_member(&record).await {
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
    row.member = Some(member);
    row.epoch = epoch;
    row.reason = Some(reason);
    if !withdrawn {
        row.note = Some(REMOVAL_NOTICE.into());
    }
    audit(state, &actor.did, row).await;

    // Item 4: the structured members say what removal did; the notice beside them in
    // `ext` is a courtesy a caller must not depend on (#796).
    let mut body = json!({
        "member": record.wire(),
        "ext": { "org.openvtc": { "notice": REMOVAL_NOTICE } },
    });
    if let Some(e) = epoch.filter(|e| *e >= 2) {
        body["epoch"] = json!(e);
    }
    respond::<remove::Response>(&doc, body)
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
) -> TrustTaskOutcome {
    use crate::rooms::community::codes as c;
    let signer = match active_signer(state, ctx, &doc, c::OFFERS_LIST_NOT_A_MEMBER).await {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let checked: offers_list::Payload = match parse_spec_payload(&doc) {
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
    let records = match state.community_rooms.records_of(&signer).await {
        Ok(r) => r
            .into_iter()
            .filter(|r| {
                r.credentials.is_some() && (r.state == MemberRecord::OFFERED || r.welcome_kept(at))
            })
            .collect::<Vec<_>>(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let (records, next) = match page(
        &doc,
        records,
        |r| r.room_id.clone(),
        OFFERS_CURSOR,
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
        let Some(credentials) = &r.credentials else {
            continue;
        };
        items.push(json!({
            "roomId": r.room_id,
            "host": host,
            "label": room.label,
            "visibility": room.visibility,
            "actions": r.actions,
            "validUntil": r.valid_until,
            "offeredAt": r.offered_at,
            "state": if r.state == MemberRecord::OFFERED { "open" } else { "accepted" },
            "credentials": credentials,
        }));
    }
    let mut body = json!({ "items": items });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    respond::<offers_list::Response>(&doc, body)
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
        // 0.2 first, whose answer to a repeat of an admission whose reply was lost is its
        // Welcome (item 8). A VTA that does not serve 0.2 never routed the ask, so asking
        // again at 0.1 — which takes the same request — is not a second admission.
        let asked = match ask(&holder, OWNER_GROUP_ADD, request.clone(), ADVANCE_TIMEOUT).await {
            Err(HolderError::Refused { code, .. })
                if matches!(code.as_str(), "unsupportedType" | "unsupportedVersion") =>
            {
                ask(&holder, OWNER_GROUP_ADD_V0_1, request, ADVANCE_TIMEOUT).await
            }
            other => other,
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
            Err(HolderError::Refused { code, message }) => {
                return refuse(
                    &doc,
                    c::ACCEPT_KEY_HOLDER_REFUSED,
                    format!("the community's VTA refused: {code} {message}"),
                    Some(HolderError::refused_details(&code, &message)),
                );
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
