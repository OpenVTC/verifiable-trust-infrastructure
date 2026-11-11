//! `vtc/badges/*` (VTI Community Badges chapter, VTI-BDG-001 – 095): member badges.
//!
//! A community badge is a badge group ([`crate::badges`]): `create` makes the group as
//! `vtc/groups/create` does, its managers are the badge's owners, its members the holders,
//! and `mine/accept` issues the badge credential as the group's DID **before** recording
//! the membership, the order every group admission keeps. A kudos badge has no group.
//!
//! Who signs: the holder's tasks (`mine/*`, `kudos/give`, `wall/show`, `holders/list`,
//! `list`, `show`, `images/get`, and a member's `images/upload` and `create` of a kudos
//! badge) accept the portal's delegated key for the member's live session
//! (`member_portal::delegation`, VTI-BDG-095); the administrators' and owners' tasks go
//! through `member_signer` only and never do. Every write is audited by reference
//! (`BadgeChanged`), never a note or a picture (VTI-BDG-091).

use std::collections::BTreeSet;

use base64::Engine as _;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::BadgeChangedData;
use vti_common::error::AppError;
use vti_specs::vtc::badges::{
    awards::{
        list::v0_1 as awards_list, offer::v0_1 as awards_offer, revoke::v0_1 as awards_revoke,
        share::v0_1 as awards_share, unshare::v0_1 as awards_unshare,
        withdraw::v0_1 as awards_withdraw,
    },
    claims::{
        create::v0_1 as claims_create, list::v0_1 as claims_list, redeem::v0_1 as claims_redeem,
        withdraw::v0_1 as claims_withdraw,
    },
    create::v0_1 as badge_create,
    holders::list::v0_1 as holders_list,
    images::{get::v0_1 as images_get, upload::v0_1 as images_upload},
    kudos::{give::v0_1 as kudos_give, list::v0_1 as kudos_list},
    list::v0_1 as badge_list,
    mine::{
        accept::v0_1 as mine_accept, arrange::v0_1 as mine_arrange, decline::v0_1 as mine_decline,
        hide::v0_1 as mine_hide, list::v0_1 as mine_list, show::v0_1 as mine_show,
    },
    promote::v0_1 as badge_promote,
    retire::v0_1 as badge_retire,
    settings::{show::v0_1 as settings_show, update::v0_1 as settings_update},
    show::v0_1 as badge_show,
    update::v0_1 as badge_update,
    wall::show::v0_1 as wall_show,
};

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::acl::Capability;
use crate::badges::{
    self, Award, AwardState, Badge, BadgeKind, BadgeState, Holding, Prefs, Settings,
};
use crate::directory::images::{self, Owner, UploadError};
use crate::groups::identity::{self, Failure};
use crate::groups::{self, Group, Membership, Standing};
use crate::rooms::community::HolderError;
use crate::server::AppState;

pub(crate) const SETTINGS_SHOW_TYPE: &str = <settings_show::Payload as Payload>::TYPE_URI;
pub(crate) const SETTINGS_UPDATE_TYPE: &str = <settings_update::Payload as Payload>::TYPE_URI;
pub(crate) const CREATE_TYPE: &str = <badge_create::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <badge_update::Payload as Payload>::TYPE_URI;
pub(crate) const RETIRE_TYPE: &str = <badge_retire::Payload as Payload>::TYPE_URI;
pub(crate) const PROMOTE_TYPE: &str = <badge_promote::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <badge_list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <badge_show::Payload as Payload>::TYPE_URI;
pub(crate) const IMAGES_UPLOAD_TYPE: &str = <images_upload::Payload as Payload>::TYPE_URI;
pub(crate) const IMAGES_GET_TYPE: &str = <images_get::Payload as Payload>::TYPE_URI;
pub(crate) const AWARDS_OFFER_TYPE: &str = <awards_offer::Payload as Payload>::TYPE_URI;
pub(crate) const AWARDS_WITHDRAW_TYPE: &str = <awards_withdraw::Payload as Payload>::TYPE_URI;
pub(crate) const AWARDS_REVOKE_TYPE: &str = <awards_revoke::Payload as Payload>::TYPE_URI;
pub(crate) const AWARDS_LIST_TYPE: &str = <awards_list::Payload as Payload>::TYPE_URI;
pub(crate) const CLAIMS_CREATE_TYPE: &str = <claims_create::Payload as Payload>::TYPE_URI;

/// Tasks whose response carries a claim code, answered once: the community
/// keeps only its digest, and the duplicate-execution record keeps no copy
/// either. A redelivery is answered `204`.
pub(crate) const SECRET_RESPONSES: &[&str] = &[CLAIMS_CREATE_TYPE];
pub(crate) const CLAIMS_LIST_TYPE: &str = <claims_list::Payload as Payload>::TYPE_URI;
pub(crate) const CLAIMS_WITHDRAW_TYPE: &str = <claims_withdraw::Payload as Payload>::TYPE_URI;
pub(crate) const CLAIMS_REDEEM_TYPE: &str = <claims_redeem::Payload as Payload>::TYPE_URI;
pub(crate) const AWARDS_SHARE_TYPE: &str = <awards_share::Payload as Payload>::TYPE_URI;
pub(crate) const AWARDS_UNSHARE_TYPE: &str = <awards_unshare::Payload as Payload>::TYPE_URI;
pub(crate) const HOLDERS_LIST_TYPE: &str = <holders_list::Payload as Payload>::TYPE_URI;
pub(crate) const WALL_SHOW_TYPE: &str = <wall_show::Payload as Payload>::TYPE_URI;
pub(crate) const MINE_LIST_TYPE: &str = <mine_list::Payload as Payload>::TYPE_URI;
pub(crate) const MINE_ACCEPT_TYPE: &str = <mine_accept::Payload as Payload>::TYPE_URI;
pub(crate) const MINE_DECLINE_TYPE: &str = <mine_decline::Payload as Payload>::TYPE_URI;
pub(crate) const MINE_HIDE_TYPE: &str = <mine_hide::Payload as Payload>::TYPE_URI;
pub(crate) const MINE_SHOW_TYPE: &str = <mine_show::Payload as Payload>::TYPE_URI;
pub(crate) const MINE_ARRANGE_TYPE: &str = <mine_arrange::Payload as Payload>::TYPE_URI;
pub(crate) const KUDOS_GIVE_TYPE: &str = <kudos_give::Payload as Payload>::TYPE_URI;
pub(crate) const KUDOS_LIST_TYPE: &str = <kudos_list::Payload as Payload>::TYPE_URI;

/// Every type this module serves.
pub(crate) const URIS: &[&str] = &[
    SETTINGS_SHOW_TYPE,
    SETTINGS_UPDATE_TYPE,
    CREATE_TYPE,
    UPDATE_TYPE,
    RETIRE_TYPE,
    PROMOTE_TYPE,
    LIST_TYPE,
    SHOW_TYPE,
    IMAGES_UPLOAD_TYPE,
    IMAGES_GET_TYPE,
    AWARDS_OFFER_TYPE,
    AWARDS_WITHDRAW_TYPE,
    AWARDS_REVOKE_TYPE,
    AWARDS_LIST_TYPE,
    AWARDS_SHARE_TYPE,
    AWARDS_UNSHARE_TYPE,
    CLAIMS_CREATE_TYPE,
    CLAIMS_LIST_TYPE,
    CLAIMS_WITHDRAW_TYPE,
    CLAIMS_REDEEM_TYPE,
    HOLDERS_LIST_TYPE,
    WALL_SHOW_TYPE,
    MINE_LIST_TYPE,
    MINE_ACCEPT_TYPE,
    MINE_DECLINE_TYPE,
    MINE_HIDE_TYPE,
    MINE_SHOW_TYPE,
    MINE_ARRANGE_TYPE,
    KUDOS_GIVE_TYPE,
    KUDOS_LIST_TYPE,
];

macro_rules! codes {
    ($($name:ident = $module:ident :: $code:ident;)*) => {
        $(pub(crate) const $name: &str = $module::error_codes::$code.code;)*
    };
}

codes! {
    SETTINGS_ERR_INVALID = settings_update::SETTINGS_INVALID;
    CREATE_ERR_BADGES_OFF = badge_create::BADGES_OFF;
    CREATE_ERR_KIND_NOT_PERMITTED = badge_create::KIND_NOT_PERMITTED;
    CREATE_ERR_LIMIT_REACHED = badge_create::LIMIT_REACHED;
    CREATE_ERR_IMAGE_NOT_FOUND = badge_create::IMAGE_NOT_FOUND;
    CREATE_ERR_SETTINGS_INVALID = badge_create::SETTINGS_INVALID;
    CREATE_ERR_RULE_INVALID = badge_create::RULE_INVALID;
    CREATE_ERR_OWNER_NOT_ELIGIBLE = badge_create::OWNER_NOT_ELIGIBLE;
    CREATE_ERR_NO_KEY_HOLDER = badge_create::NO_KEY_HOLDER;
    CREATE_ERR_KEY_HOLDER_UNAVAILABLE = badge_create::KEY_HOLDER_UNAVAILABLE;
    CREATE_ERR_KEY_HOLDER_REFUSED = badge_create::KEY_HOLDER_REFUSED;
    UPDATE_ERR_BADGES_OFF = badge_update::BADGES_OFF;
    UPDATE_ERR_BADGE_RETIRED = badge_update::BADGE_RETIRED;
    UPDATE_ERR_IMAGE_NOT_FOUND = badge_update::IMAGE_NOT_FOUND;
    UPDATE_ERR_SETTINGS_INVALID = badge_update::SETTINGS_INVALID;
    RETIRE_ERR_BADGES_OFF = badge_retire::BADGES_OFF;
    RETIRE_ERR_ALREADY_RETIRED = badge_retire::ALREADY_RETIRED;
    RETIRE_ERR_KEY_HOLDER_UNAVAILABLE = badge_retire::KEY_HOLDER_UNAVAILABLE;
    RETIRE_ERR_KEY_HOLDER_REFUSED = badge_retire::KEY_HOLDER_REFUSED;
    PROMOTE_ERR_BADGES_OFF = badge_promote::BADGES_OFF;
    PROMOTE_ERR_BADGE_RETIRED = badge_promote::BADGE_RETIRED;
    PROMOTE_ERR_KIND_MISMATCH = badge_promote::KIND_MISMATCH;
    PROMOTE_ERR_SETTINGS_INVALID = badge_promote::SETTINGS_INVALID;
    PROMOTE_ERR_OWNER_NOT_ELIGIBLE = badge_promote::OWNER_NOT_ELIGIBLE;
    PROMOTE_ERR_NO_KEY_HOLDER = badge_promote::NO_KEY_HOLDER;
    PROMOTE_ERR_KEY_HOLDER_UNAVAILABLE = badge_promote::KEY_HOLDER_UNAVAILABLE;
    PROMOTE_ERR_KEY_HOLDER_REFUSED = badge_promote::KEY_HOLDER_REFUSED;
    LIST_ERR_CURSOR_INVALID = badge_list::CURSOR_INVALID;
    UPLOAD_ERR_BADGES_OFF = images_upload::BADGES_OFF;
    UPLOAD_ERR_NOT_MEMBER = images_upload::NOT_MEMBER;
    UPLOAD_ERR_TOO_LARGE = images_upload::TOO_LARGE;
    UPLOAD_ERR_NOT_AN_IMAGE = images_upload::NOT_AN_IMAGE;
    UPLOAD_ERR_RATE_LIMITED = images_upload::RATE_LIMITED;
    GET_ERR_NOT_FOUND = images_get::NOT_FOUND;
    OFFER_ERR_BADGES_OFF = awards_offer::BADGES_OFF;
    OFFER_ERR_BADGE_RETIRED = awards_offer::BADGE_RETIRED;
    OFFER_ERR_KIND_MISMATCH = awards_offer::KIND_MISMATCH;
    OFFER_ERR_AUTOMATIC_BADGE = awards_offer::AUTOMATIC_BADGE;
    OFFER_ERR_GROUP_NOT_VISIBLE = awards_offer::GROUP_NOT_VISIBLE;
    OFFER_ERR_NOTHING_TO_OFFER = awards_offer::NOTHING_TO_OFFER;
    WITHDRAW_ERR_BADGES_OFF = awards_withdraw::BADGES_OFF;
    WITHDRAW_ERR_NOT_FOUND = awards_withdraw::NOT_FOUND;
    WITHDRAW_ERR_ALREADY_DECIDED = awards_withdraw::ALREADY_DECIDED;
    REVOKE_ERR_BADGES_OFF = awards_revoke::BADGES_OFF;
    REVOKE_ERR_NOT_FOUND = awards_revoke::NOT_FOUND;
    REVOKE_ERR_NOT_ACCEPTED = awards_revoke::NOT_ACCEPTED;
    REVOKE_ERR_KEY_HOLDER_UNAVAILABLE = awards_revoke::KEY_HOLDER_UNAVAILABLE;
    REVOKE_ERR_KEY_HOLDER_REFUSED = awards_revoke::KEY_HOLDER_REFUSED;
    AWARDS_LIST_ERR_NOT_FOUND = awards_list::NOT_FOUND;
    SHARE_ERR_BADGES_OFF = awards_share::BADGES_OFF;
    SHARE_ERR_NOT_FOUND = awards_share::NOT_FOUND;
    SHARE_ERR_NOT_SHAREABLE = awards_share::NOT_SHAREABLE;
    SHARE_ERR_PUBLIC_LOCATION_UNAVAILABLE = awards_share::PUBLIC_LOCATION_UNAVAILABLE;
    UNSHARE_ERR_BADGES_OFF = awards_unshare::BADGES_OFF;
    UNSHARE_ERR_NOT_FOUND = awards_unshare::NOT_FOUND;
    CLAIMS_CREATE_ERR_BADGES_OFF = claims_create::BADGES_OFF;
    CLAIMS_CREATE_ERR_NOT_FOUND = claims_create::NOT_FOUND;
    CLAIMS_CREATE_ERR_NOT_CLAIMABLE = claims_create::NOT_CLAIMABLE;
    CLAIMS_CREATE_ERR_SETTINGS_INVALID = claims_create::SETTINGS_INVALID;
    CLAIMS_LIST_ERR_NOT_FOUND = claims_list::NOT_FOUND;
    CLAIMS_LIST_ERR_CURSOR_INVALID = claims_list::CURSOR_INVALID;
    CLAIMS_WITHDRAW_ERR_BADGES_OFF = claims_withdraw::BADGES_OFF;
    CLAIMS_WITHDRAW_ERR_NOT_FOUND = claims_withdraw::NOT_FOUND;
    REDEEM_ERR_BADGES_OFF = claims_redeem::BADGES_OFF;
    REDEEM_ERR_CODE_INVALID = claims_redeem::CODE_INVALID;
    REDEEM_ERR_ALREADY_CLAIMED = claims_redeem::ALREADY_CLAIMED;
    REDEEM_ERR_ALREADY_HELD = claims_redeem::ALREADY_HELD;
    REDEEM_ERR_KEY_HOLDER_UNAVAILABLE = claims_redeem::KEY_HOLDER_UNAVAILABLE;
    REDEEM_ERR_KEY_HOLDER_REFUSED = claims_redeem::KEY_HOLDER_REFUSED;
    AWARDS_LIST_ERR_CURSOR_INVALID = awards_list::CURSOR_INVALID;
    HOLDERS_ERR_NOT_FOUND = holders_list::NOT_FOUND;
    HOLDERS_ERR_CURSOR_INVALID = holders_list::CURSOR_INVALID;
    WALL_ERR_NOT_FOUND = wall_show::NOT_FOUND;
    ACCEPT_ERR_BADGES_OFF = mine_accept::BADGES_OFF;
    ACCEPT_ERR_ALREADY_DECIDED = mine_accept::ALREADY_DECIDED;
    ACCEPT_ERR_BADGE_RETIRED = mine_accept::BADGE_RETIRED;
    ACCEPT_ERR_KEY_HOLDER_UNAVAILABLE = mine_accept::KEY_HOLDER_UNAVAILABLE;
    ACCEPT_ERR_KEY_HOLDER_REFUSED = mine_accept::KEY_HOLDER_REFUSED;
    DECLINE_ERR_BADGES_OFF = mine_decline::BADGES_OFF;
    DECLINE_ERR_ALREADY_DECIDED = mine_decline::ALREADY_DECIDED;
    HIDE_ERR_BADGES_OFF = mine_hide::BADGES_OFF;
    SHOW_AGAIN_ERR_BADGES_OFF = mine_show::BADGES_OFF;
    ARRANGE_ERR_BADGES_OFF = mine_arrange::BADGES_OFF;
    ARRANGE_ERR_BADGE_NOT_HELD = mine_arrange::BADGE_NOT_HELD;
    ARRANGE_ERR_TOO_MANY_PINNED = mine_arrange::TOO_MANY_PINNED;
    ARRANGE_ERR_BADGE_HIDDEN = mine_arrange::BADGE_HIDDEN;
    KUDOS_ERR_BADGES_OFF = kudos_give::BADGES_OFF;
    KUDOS_ERR_KIND_MISMATCH = kudos_give::KIND_MISMATCH;
    KUDOS_ERR_SELF_GIVING = kudos_give::SELF_GIVING;
    KUDOS_ERR_NOT_ELIGIBLE = kudos_give::NOT_ELIGIBLE;
    KUDOS_ERR_LIMIT_REACHED = kudos_give::LIMIT_REACHED;
    KUDOS_LIST_ERR_CURSOR_INVALID = kudos_list::CURSOR_INVALID;
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        SETTINGS_SHOW_TYPE => handle_settings_show(state, ctx, doc).await,
        SETTINGS_UPDATE_TYPE => handle_settings_update(state, ctx, doc).await,
        CREATE_TYPE => handle_create(state, ctx, doc).await,
        UPDATE_TYPE => handle_update(state, ctx, doc).await,
        RETIRE_TYPE => handle_retire(state, ctx, doc).await,
        PROMOTE_TYPE => handle_promote(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        IMAGES_UPLOAD_TYPE => handle_images_upload(state, ctx, doc).await,
        IMAGES_GET_TYPE => handle_images_get(state, ctx, doc).await,
        AWARDS_OFFER_TYPE => handle_offer(state, ctx, doc).await,
        AWARDS_WITHDRAW_TYPE => handle_withdraw(state, ctx, doc).await,
        AWARDS_REVOKE_TYPE => handle_revoke(state, ctx, doc).await,
        AWARDS_LIST_TYPE => handle_awards_list(state, ctx, doc).await,
        AWARDS_SHARE_TYPE => handle_share(state, ctx, doc).await,
        CLAIMS_CREATE_TYPE => handle_claims_create(state, ctx, doc).await,
        CLAIMS_LIST_TYPE => handle_claims_list(state, ctx, doc).await,
        CLAIMS_WITHDRAW_TYPE => handle_claims_withdraw(state, ctx, doc).await,
        CLAIMS_REDEEM_TYPE => handle_claims_redeem(state, ctx, doc).await,
        AWARDS_UNSHARE_TYPE => handle_unshare(state, ctx, doc).await,
        HOLDERS_LIST_TYPE => handle_holders_list(state, ctx, doc).await,
        WALL_SHOW_TYPE => handle_wall_show(state, ctx, doc).await,
        MINE_LIST_TYPE => handle_mine_list(state, ctx, doc).await,
        MINE_ACCEPT_TYPE => handle_accept(state, ctx, doc).await,
        MINE_DECLINE_TYPE => handle_decline(state, ctx, doc).await,
        MINE_HIDE_TYPE => handle_hide(state, ctx, doc, true).await,
        MINE_SHOW_TYPE => handle_hide(state, ctx, doc, false).await,
        MINE_ARRANGE_TYPE => handle_arrange(state, ctx, doc).await,
        KUDOS_GIVE_TYPE => handle_kudos_give(state, ctx, doc).await,
        KUDOS_LIST_TYPE => handle_kudos_list(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── shared ──────────────────────────────────────────────────────────────

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

fn declared_with(
    doc: &TrustTask<Value>,
    code: &str,
    message: impl Into<String>,
    details: Value,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, Some(details))
}

fn denied(doc: &TrustTask<Value>, why: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: why.to_string(),
        },
    )
}

fn not_found(doc: &TrustTask<Value>, what: &str) -> TrustTaskOutcome {
    app_error_to_reject(
        doc,
        &AppError::NotFound(format!("no {what} you may see has this identifier")),
    )
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn bool_of(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

fn string_list(v: &Value, key: &str) -> Option<Vec<String>> {
    v.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

fn reason_of(doc: &TrustTask<Value>) -> Option<String> {
    str_of(&doc.payload, "reason").map(str::to_string)
}

/// A member's act: the signer's own key, or the portal's key for the member's live
/// session (VTI-BDG-095).
async fn member(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Standing, TrustTaskOutcome> {
    let delegated = match ctx.verified_signer.as_deref() {
        Some(signer) => crate::member_portal::delegation::accept(
            state,
            signer,
            &doc.type_uri.to_string(),
            &doc.id.to_string(),
        )
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?,
        None => None,
    };
    let did = match delegated {
        Some(m) => m,
        None => member_signer(state, ctx, doc).await?.did,
    };
    Standing::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// An administrator's or owner's act: the signer's own key only — never the portal's
/// delegated key (VTI-BDG-095), which `member_signer` does not accept.
async fn signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<Standing, TrustTaskOutcome> {
    let did = member_signer(state, ctx, doc).await?.did;
    Standing::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// A badge change is never unaudited (VTI-BDG-091).
async fn audit(state: &AppState, actor: &str, data: BadgeChangedData) -> Result<(), AppError> {
    badges::audit(state, actor, data).await
}

fn changed(badge_id: &str, change: &str) -> BadgeChangedData {
    BadgeChangedData {
        badge_id: badge_id.to_string(),
        award_id: None,
        entry_id: None,
        change: change.to_string(),
        fields: Vec::new(),
        group_id: None,
    }
}

fn award_changed(a: &Award, change: &str) -> BadgeChangedData {
    BadgeChangedData {
        badge_id: a.badge_id.clone(),
        award_id: Some(a.award_id.clone()),
        entry_id: Some(a.entry_id.clone()),
        change: change.to_string(),
        fields: Vec::new(),
        group_id: None,
    }
}

/// The requester's gesture bound to this document (VTI-OPS-050): `Ok(())` once spent,
/// the refusal asking for it otherwise.
async fn bound_step_up(
    state: &AppState,
    actor: &str,
    doc: &TrustTask<Value>,
    reason: &str,
) -> Result<(), TrustTaskOutcome> {
    use crate::acl::bound_step_up::{self, Gate};
    use crate::error::TaskError;
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

fn holder_refusal(
    doc: &TrustTask<Value>,
    unavailable: &str,
    refused: &str,
    e: HolderError,
    group_did: Option<String>,
) -> TrustTaskOutcome {
    match e {
        HolderError::Unavailable(why) => match group_did {
            Some(d) => declared_with(doc, unavailable, why, json!({ "groupDid": d })),
            None => declared(doc, unavailable, why),
        },
        HolderError::Refused { code, message } => declared_with(
            doc,
            refused,
            format!("the community's VTA refused: {code} {message}"),
            HolderError::refused_details(&code, &message),
        ),
    }
}

fn failure_refusal(
    doc: &TrustTask<Value>,
    f: Failure,
    unavailable: &str,
    refused: &str,
) -> TrustTaskOutcome {
    match f {
        Failure::Local(e) => app_error_to_reject(doc, &e),
        Failure::Holder(e, did) => holder_refusal(doc, unavailable, refused, e, did),
    }
}

/// The settings, refusing with `code` while badges are off (VTI-BDG-004).
async fn settings_on(
    state: &AppState,
    doc: &TrustTask<Value>,
    code: &str,
) -> Result<Settings, TrustTaskOutcome> {
    let s = badges::settings(&state.badges_ks)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    if !s.enabled {
        return Err(declared(doc, code, "This community has badges turned off."));
    }
    Ok(s)
}

/// The caller's directory entry, made if they have none yet (as groups do).
async fn own_entry(state: &AppState, who: &Standing) -> Result<String, AppError> {
    if let Some(e) = &who.entry_id {
        return Ok(e.clone());
    }
    let dir = &state.directory;
    let own = crate::acl::get_acl_entry(&state.acl_ks, &who.did)
        .await?
        .filter(|e| e.label_set_by_subject)
        .and_then(|e| e.label);
    Ok(
        crate::directory::cards::ensure(dir.ks(), &who.did, &dir.settings(), own.as_deref())
            .await?
            .entry_id,
    )
}

/// `entry_id`'s membership DID, where they are an active member.
async fn active_entry(state: &AppState, entry_id: &str) -> Result<Option<String>, AppError> {
    let Some(card) = crate::directory::cards::get(state.directory.ks(), entry_id).await? else {
        return Ok(None);
    };
    Ok(
        crate::member_portal::active::active_member(state, &card.did)
            .await?
            .map(|_| card.did),
    )
}

/// Whether the directory shows `viewer` the entry at all (VTI-DIR-110): a member they
/// may address, whatever fields it shows them.
async fn directory_shows(
    state: &AppState,
    viewer: &crate::directory::project::Viewer,
    entry_id: &str,
) -> bool {
    use crate::directory::read::{ShowBy, show};
    show(state, viewer, &ShowBy::Entry(entry_id.to_string()))
        .await
        .is_ok()
}

/// An entry's fields as `vtc/directory/entries/show` projects them for `viewer`; `None`
/// where it shows them none. `show` answers that task's payload, `{ "entry": { …,
/// "fields" } }`, so the fields are the entry's, one level down.
async fn projected_fields(
    state: &AppState,
    viewer: &crate::directory::project::Viewer,
    entry_id: &str,
) -> Option<Value> {
    use crate::directory::read::{ShowBy, show};
    match show(state, viewer, &ShowBy::Entry(entry_id.to_string())).await {
        Ok(shown) => shown
            .get("entry")
            .and_then(|e| e.get("fields"))
            .filter(|f| f.as_object().is_some_and(|o| !o.is_empty()))
            .cloned(),
        Err(_) => None,
    }
}

// ── paging: an offset bound to the caller and the question ──

fn cursor_mac(binding: &str, offset: usize) -> String {
    let mut h = Sha256::new();
    h.update(b"vtc/badges/cursor/v1\0");
    for part in [binding, &offset.to_string()] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..12])
}

fn cursor_for(binding: &str, offset: usize) -> String {
    format!("{offset}.{}", cursor_mac(binding, offset))
}

fn offset_of(payload: &Value, binding: &str) -> Result<usize, ()> {
    let Some(c) = str_of(payload, "cursor") else {
        return Ok(0);
    };
    let (n, mac) = c.split_once('.').ok_or(())?;
    let offset: usize = n.parse().map_err(|_| ())?;
    (cursor_mac(binding, offset) == mac)
        .then_some(offset)
        .ok_or(())
}

fn limit_of(payload: &Value) -> usize {
    payload
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(50, |l| l as usize)
        .clamp(1, 200)
}

/// One page of `items`, and the cursor to the next, where there is one.
fn page<T: Clone>(
    items: &[T],
    offset: usize,
    limit: usize,
    binding: &str,
) -> (Vec<T>, Option<String>) {
    let end = (offset + limit).min(items.len());
    let next = (end < items.len()).then(|| cursor_for(binding, end));
    (items[offset.min(items.len())..end].to_vec(), next)
}

// ── what the caller may see ──

/// The caller's standing beside a badge.
struct View {
    who: Standing,
    entry_id: Option<String>,
    admin: bool,
    settings: Settings,
    /// What the caller holds, by badge.
    holdings: std::collections::BTreeMap<String, Holding>,
    /// Open offers to the caller, by badge.
    offered: BTreeSet<String>,
}

impl View {
    async fn read(state: &AppState, who: Standing) -> Result<Self, AppError> {
        let settings = badges::settings(&state.badges_ks).await?;
        let admin = who.can(Capability::BadgesAdmin);
        let (holdings, offered) = match &who.entry_id {
            Some(e) => (
                badges::holdings_of(&state.badges_ks, e).await?,
                badges::awards_to(&state.badges_ks, e)
                    .await?
                    .into_iter()
                    .filter(Award::is_open)
                    .map(|a| a.badge_id)
                    .collect(),
            ),
            None => (Default::default(), BTreeSet::new()),
        };
        Ok(View {
            entry_id: who.entry_id.clone(),
            who,
            admin,
            settings,
            holdings,
            offered,
        })
    }

    fn holds(&self, badge_id: &str) -> bool {
        self.holdings.contains_key(badge_id)
    }

    /// Does the caller own `badge`: manage its badge group.
    fn owns(&self, badge: &Badge) -> bool {
        badge
            .group_id
            .as_deref()
            .is_some_and(|g| self.who.manages(g))
    }

    /// Is the caller the maker of a kudos badge.
    fn made(&self, badge: &Badge) -> bool {
        badge.kind == BadgeKind::Kudos
            && self.entry_id.is_some()
            && badge.created_by == self.entry_id
    }

    /// May the caller see `badge` at all (the visibility rule every task shares).
    fn sees(&self, badge: &Badge) -> bool {
        if !self.settings.enabled && !self.admin {
            return false;
        }
        if self.admin || self.holds(&badge.badge_id) || self.owns(badge) || self.made(badge) {
            return true;
        }
        if self.offered.contains(&badge.badge_id) {
            return true;
        }
        badge.is_active() && badge.listed && self.who.may_read()
    }

    /// May the caller see `badge`'s holders (VTI-BDG-033).
    async fn sees_holders(&self, state: &AppState, badge: &Badge) -> Result<bool, AppError> {
        if !self.sees(badge) {
            return Ok(false);
        }
        if self.admin || self.owns(badge) {
            return Ok(true);
        }
        match &badge.group_id {
            Some(g) => Ok(groups::get(state.directory.ks(), g)
                .await?
                .is_some_and(|g| self.who.sees_members(&g))),
            None => Ok(self.who.may_read()),
        }
    }

    fn my_count(&self, badge_id: &str) -> usize {
        self.holdings.get(badge_id).map_or(0, |h| h.count)
    }

    async fn my_state(&self, state: &AppState, badge: &Badge) -> Result<&'static str, AppError> {
        if self.holds(&badge.badge_id) {
            return Ok("holder");
        }
        if self.offered.contains(&badge.badge_id) {
            return Ok("offered");
        }
        if let (Some(g), Some(e)) = (&badge.group_id, &self.entry_id)
            && groups::pending_request(state.directory.ks(), g, e)
                .await?
                .is_some()
        {
            return Ok("requested");
        }
        Ok("none")
    }

    /// `Badge` on the wire for this caller, with `holderCount` where they may see the
    /// holders.
    async fn badge_wire(&self, state: &AppState, badge: &Badge) -> Result<Value, AppError> {
        let mut out = badge.wire();
        if self.sees_holders(state, badge).await? {
            out["holderCount"] = json!(
                badges::shown_holders(&state.badges_ks, &badge.badge_id)
                    .await?
                    .len()
            );
        }
        Ok(out)
    }

    /// The badge the caller may see, else `None`.
    async fn visible(&self, state: &AppState, badge_id: &str) -> Result<Option<Badge>, AppError> {
        Ok(badges::get_badge(&state.badges_ks, badge_id)
            .await?
            .filter(|b| self.sees(b)))
    }
}

/// `MyBadge` for the holder.
async fn my_badge(
    state: &AppState,
    view: &View,
    badge: &Badge,
    h: &Holding,
    prefs: &Prefs,
    position: usize,
) -> Result<Value, AppError> {
    let mut out = json!({
        "badge": view.badge_wire(state, badge).await?,
        "count": h.count,
        "since": h.since,
        "latestAt": h.latest_at,
        "pinned": prefs.is_pinned(&badge.badge_id),
        "hidden": prefs.is_hidden(&badge.badge_id),
        "position": position,
    });
    if let Some(c) = &h.credential_id {
        out["credentialId"] = json!(c);
    }
    if let (Some(g), Some(e)) = (&badge.group_id, &view.entry_id)
        && let Some(m) = groups::membership(state.directory.ks(), g, e).await?
        && let Some(until) = m.credential_valid_until
    {
        out["credentialValidUntil"] = json!(until);
    }
    Ok(out)
}

/// The holder's whole list, in their order (`mine/list`, `mine/arrange`).
async fn my_badges(state: &AppState, view: &View, prefs: &Prefs) -> Result<Vec<Value>, AppError> {
    let held: Vec<&str> = view.holdings.keys().map(String::as_str).collect();
    let mut out = Vec::new();
    for (position, id) in prefs.arrange(held.iter().copied()).iter().enumerate() {
        let Some(badge) = badges::get_badge(&state.badges_ks, id).await? else {
            continue;
        };
        let Some(h) = view.holdings.get(id) else {
            continue;
        };
        out.push(my_badge(state, view, &badge, h, prefs, position).await?);
    }
    Ok(out)
}

// ─── settings ────────────────────────────────────────────────────────────

/// `settings/show/0.1`: any active member or administrator.
async fn handle_settings_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if !who.may_read() {
        return denied(
            &doc,
            "badge settings are read by this community's active members and administrators",
        );
    }
    if let Err(r) = parse_spec_payload::<settings_show::Payload>(&doc) {
        return r;
    }
    match badges::settings(&state.badges_ks).await {
        Ok(s) => success_response(&doc, json!({ "settings": s.wire() })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `settings/update/0.1`: `vtc.config.admin` and a bound step-up (VTI-BDG-004).
async fn handle_settings_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if !who.can(Capability::ConfigAdmin) {
        return denied(&doc, "changing badge settings takes vtc.config.admin");
    }
    if let Err(r) = parse_spec_payload::<settings_update::Payload>(&doc) {
        return r;
    }
    let mut next: Settings = match serde_json::from_value(doc.payload["settings"].clone()) {
        Ok(s) => s,
        Err(e) => {
            return declared_with(
                &doc,
                SETTINGS_ERR_INVALID,
                "The settings do not read.",
                json!({ "reason": e.to_string() }),
            );
        }
    };
    // Item: the roles and groups named exist, and no group is a badge group.
    if next.kudos_makers.policy == "roles" {
        for role in &next.kudos_makers.roles {
            let known = role.parse::<crate::acl::VtcRole>().is_ok()
                || matches!(
                    crate::acl::roles::get(&state.acl_ks, role).await,
                    Ok(Some(_))
                );
            if !known {
                return declared_with(
                    &doc,
                    SETTINGS_ERR_INVALID,
                    format!("This community defines no role {role}."),
                    json!({ "field": "kudosMakers.roles", "reason": "unknown role" }),
                );
            }
        }
        for g in &next.kudos_makers.groups {
            match groups::get(state.directory.ks(), g).await {
                Ok(Some(group)) if group.badge_id.is_none() => {}
                Ok(_) => {
                    return declared_with(
                        &doc,
                        SETTINGS_ERR_INVALID,
                        "A group named is not a community group of this community.",
                        json!({ "field": "kudosMakers.groups", "reason": "unknown group" }),
                    );
                }
                Err(e) => return app_error_to_reject(&doc, &e),
            }
        }
    } else if !next.kudos_makers.roles.is_empty() || !next.kudos_makers.groups.is_empty() {
        return declared_with(
            &doc,
            SETTINGS_ERR_INVALID,
            "Roles and groups are read only under the `roles` policy.",
            json!({ "field": "kudosMakers", "reason": "roles or groups without the roles policy" }),
        );
    }
    if let Err(r) = bound_step_up(
        state,
        &who.did,
        &doc,
        "Change the community's badge settings",
    )
    .await
    {
        return r;
    }
    let before = match badges::settings(&state.badges_ks).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut fields = Vec::new();
    if before.enabled != next.enabled {
        fields.push("enabled".to_string());
    }
    if before.kudos_makers != next.kudos_makers {
        fields.push("kudosMakers".to_string());
    }
    if before.limits != next.limits {
        fields.push("limits".to_string());
    }
    if before.show_kudos_totals != next.show_kudos_totals {
        fields.push("showKudosTotals".to_string());
    }
    if before.automatic_badges != next.automatic_badges {
        fields.push("automaticBadges".to_string());
    }
    if before.members_may_request != next.members_may_request {
        fields.push("membersMayRequest".to_string());
    }
    if before.credential_valid_days != next.credential_valid_days {
        fields.push("credentialValidDays".to_string());
    }
    next.updated_at = Some(Utc::now());
    let mut data = changed("-", "settingsChanged");
    data.fields = fields;
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_settings(&state.badges_ks, &next).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "settings": next.wire() }))
}

// ─── definitions ─────────────────────────────────────────────────────────

/// Whether `who` may make a kudos badge under `settings` (create item 2), and why not.
async fn kudos_maker(
    state: &AppState,
    who: &Standing,
    settings: &Settings,
) -> Result<Result<(), &'static str>, AppError> {
    if !who.active_member {
        return Ok(Err("only an active member makes a kudos badge"));
    }
    let admitted = match settings.kudos_makers.policy.as_str() {
        "members" => true,
        "roles" => {
            let entry = crate::acl::get_acl_entry(&state.acl_ks, &who.did).await?;
            let role_ok = entry.as_ref().is_some_and(|e| {
                settings
                    .kudos_makers
                    .roles
                    .iter()
                    .any(|r| *r == e.role.to_string())
            });
            role_ok
                || settings
                    .kudos_makers
                    .groups
                    .iter()
                    .any(|g| who.member_of.contains(g))
        }
        _ => false,
    };
    if !admitted {
        return Ok(Err(
            "this community's badge settings do not let you make a kudos badge",
        ));
    }
    if let Some(m) = crate::member_portal::active::active_member(state, &who.did).await?
        && m.member.joined_at + Duration::days(i64::from(settings.limits.min_tenure_days()))
            > Utc::now()
    {
        return Ok(Err(
            "you have not been a member long enough to make a kudos badge",
        ));
    }
    Ok(Ok(()))
}

/// The upload named by `image.sha256`, where `who` uploaded it and no other badge holds
/// it (create item 3, update): the stored `CardBlobRef`.
async fn uploaded_image(
    state: &AppState,
    who: &Standing,
    admin: bool,
    payload: &Value,
    except: Option<&str>,
) -> Result<Option<Value>, AppError> {
    let Some(sha) = payload.get("image").and_then(images::sha_of) else {
        return Ok(None);
    };
    let now = Utc::now();
    let ks = &state.badge_images_ks;
    let mut owners = Vec::new();
    if let Some(e) = &who.entry_id {
        owners.push(Owner::Member(e.clone()));
    }
    if admin {
        owners.push(Owner::Admins);
    }
    let mut mine = false;
    for o in &owners {
        if images::may_reference(ks, o, sha, now).await? {
            mine = true;
            break;
        }
    }
    if !mine || badges::image_held(&state.badges_ks, sha, except).await? {
        return Ok(None);
    }
    let Some((stored, _)) = images::get(ks, sha).await? else {
        return Ok(None);
    };
    Ok(Some(json!({
        "sha256": sha,
        "mediaType": stored.media_type,
        "size": stored.size,
    })))
}

/// What a badge group is created with (create item 5, promote).
struct GroupSpec {
    name: String,
    requestable: bool,
    show_members: groups::Audience,
    rule: Option<Value>,
}

/// Create the badge group as `vtc/groups/create` does (create items 5 – 6): mint, the
/// community's authority, then the record, with `badge_id` on it. Every remote step
/// comes before the one local write.
async fn create_group(
    state: &AppState,
    who: &Standing,
    badge_id: &str,
    spec: &GroupSpec,
    codes: (&str, &str, &str),
) -> Result<Group, Box<dyn FnOnce(&TrustTask<Value>) -> TrustTaskOutcome + Send>> {
    let (no_key_holder, unavailable, refused) = codes;
    let setup = match identity::setup(state).await {
        Ok(s) => s,
        Err(why) => {
            let code = no_key_holder.to_string();
            return Err(Box::new(move |doc| declared(doc, &code, why)));
        }
    };
    let minted = match identity::mint(state, &setup, true).await {
        Ok(m) => m,
        Err(f) => {
            let (u, r) = (unavailable.to_string(), refused.to_string());
            return Err(Box::new(move |doc| failure_refusal(doc, f, &u, &r)));
        }
    };
    let now = Utc::now();
    let (authority, authority_credential) = match minted.authority {
        Some((a, c)) => (Some(a), Some(c)),
        None => (None, None),
    };
    let dynamic = spec.rule.is_some();
    let group = Group {
        group_id: groups::new_group_id(),
        group_did: minted.group_did,
        signing_key_id: minted.signing_key_id,
        name: spec.name.clone(),
        description: None,
        kind: if dynamic {
            groups::GroupKind::Dynamic
        } else {
            groups::GroupKind::Static
        },
        rule: spec.rule.clone(),
        join_policy: if spec.requestable && !dynamic {
            groups::JoinPolicy::Request
        } else {
            groups::JoinPolicy::Closed
        },
        visibility: groups::Audience::Members,
        show_members: spec.show_members,
        issues_credentials: true,
        authority,
        authority_credential,
        did_log_path: minted.did_log_path,
        badge_id: Some(badge_id.to_string()),
        created_at: now,
        created_by: who.entry_id.clone(),
        updated_at: now,
    };
    Ok(group)
}

/// Appoint `owners` managers of `group` (create item 5), each a resource grant the
/// signer covers.
async fn appoint_owners(
    state: &AppState,
    who: &Standing,
    group_id: &str,
    owners: &[String],
    reason: Option<String>,
) -> Result<(), AppError> {
    for entry_id in owners {
        let Some(did) = active_entry(state, entry_id).await? else {
            continue;
        };
        if did == who.did {
            continue;
        }
        groups::managers::appoint(state, &who.did, &did, group_id, reason.clone()).await?;
    }
    Ok(())
}

/// Every entry in `owners` is an active member (create item 5); the first that is not.
async fn owners_eligible(state: &AppState, owners: &[String]) -> Result<Option<String>, AppError> {
    for e in owners {
        if active_entry(state, e).await?.is_none() {
            return Ok(Some(e.clone()));
        }
    }
    Ok(None)
}

/// `create/0.1` (items 1 – 8).
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // A kudos badge is a member's act (delegated key accepted); a community badge an
    // administrator's. Read the signer the permissive way first, then tighten.
    let p = doc.payload.clone();
    let kind = str_of(&p, "kind").and_then(BadgeKind::parse);
    let who = match kind {
        Some(BadgeKind::Community) => signer(state, ctx, &doc).await,
        _ => member(state, ctx, &doc).await,
    };
    let who = match who {
        Ok(w) => w,
        Err(r) => return r,
    };
    let settings = match settings_on(state, &doc, CREATE_ERR_BADGES_OFF).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<badge_create::Payload>(&doc) {
        return r;
    }
    let Some(kind) = kind else {
        return app_error_to_reject(&doc, &AppError::Validation("unreadable kind".into()));
    };
    let admin = who.can(Capability::BadgesAdmin);
    // Item 2.
    match kind {
        BadgeKind::Community if !admin => {
            return declared(
                &doc,
                CREATE_ERR_KIND_NOT_PERMITTED,
                "Defining a community badge takes vtc.badges.admin.",
            );
        }
        BadgeKind::Kudos => {
            match kudos_maker(state, &who, &settings).await {
                Ok(Ok(())) => {}
                Ok(Err(why)) => return declared(&doc, CREATE_ERR_KIND_NOT_PERMITTED, why),
                Err(e) => return app_error_to_reject(&doc, &e),
            }
            let month_ago = Utc::now() - Duration::days(30);
            let made = match badges::all_badges(&state.badges_ks).await {
                Ok(b) => b
                    .iter()
                    .filter(|b| {
                        b.kind == BadgeKind::Kudos
                            && b.created_by == who.entry_id
                            && b.created_at > month_ago
                    })
                    .count(),
                Err(e) => return app_error_to_reject(&doc, &e),
            };
            if made >= settings.limits.kudos_badges_per_maker_per_month() as usize {
                return declared(
                    &doc,
                    CREATE_ERR_LIMIT_REACHED,
                    "You have made as many kudos badges as this community allows this month.",
                );
            }
        }
        _ => {}
    }
    // Item 4: the settings that fit the kind.
    let has = |k: &str| p.get(k).is_some();
    let invalid = |doc: &TrustTask<Value>, field: &str, why: &str| {
        declared_with(
            doc,
            CREATE_ERR_SETTINGS_INVALID,
            why,
            json!({ "field": field, "reason": why }),
        )
    };
    if kind == BadgeKind::Kudos {
        for k in [
            "requestable",
            "shareableOutside",
            "holdersVisibleTo",
            "automatic",
            "owners",
        ] {
            if has(k) {
                return invalid(&doc, k, "A kudos badge takes no such setting.");
            }
        }
        if bool_of(&p, "repeatable") == Some(false) {
            return invalid(&doc, "repeatable", "A kudos badge is always repeatable.");
        }
    }
    let requestable = bool_of(&p, "requestable").unwrap_or(false);
    let automatic = p.get("automatic").and_then(|a| a.get("rule")).cloned();
    if requestable && automatic.is_some() {
        return invalid(
            &doc,
            "requestable",
            "An automatic badge is given by its rule, never asked for.",
        );
    }
    if requestable && !settings.members_may_request {
        return invalid(
            &doc,
            "requestable",
            "This community does not let members ask for badges.",
        );
    }
    if automatic.is_some() && !settings.automatic_badges {
        return invalid(
            &doc,
            "automatic",
            "This community has automatic badges turned off.",
        );
    }
    if let Some(rule) = &automatic {
        let schema = match crate::directory::fields::schema(state.directory.ks()).await {
            Ok(s) => s,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if let Err(e) = groups::check_badge_rule(rule, &schema) {
            let mut details = json!({ "reason": e.reason.clone() });
            if let Some(f) = &e.field {
                details["field"] = json!(f);
            }
            return declared_with(&doc, CREATE_ERR_RULE_INVALID, e.reason, details);
        }
    }
    // Item 3: the picture.
    let image = match uploaded_image(state, &who, admin, &p, None).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return declared(
                &doc,
                CREATE_ERR_IMAGE_NOT_FOUND,
                "Upload the picture with vtc/badges/images/upload first; a digest is accepted \
                 only from your own upload that no badge holds yet.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 5: the owners, before anything is minted.
    let owners = string_list(&p, "owners").unwrap_or_default();
    if kind == BadgeKind::Community {
        if !owners.is_empty() && !who.manages_all {
            return declared(
                &doc,
                CREATE_ERR_OWNER_NOT_ELIGIBLE,
                "Appointing owners takes vtc.groups.manage at the community.",
            );
        }
        match owners_eligible(state, &owners).await {
            Ok(None) => {}
            Ok(Some(e)) => {
                return declared_with(
                    &doc,
                    CREATE_ERR_OWNER_NOT_ELIGIBLE,
                    "An owner named is not an active member.",
                    json!({ "entryId": e }),
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let now = Utc::now();
    let entry_id = match own_entry(state, &who).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut badge = Badge {
        badge_id: badges::new_badge_id(),
        kind,
        name: str_of(&p, "name").unwrap_or_default().to_string(),
        description: str_of(&p, "description").unwrap_or_default().to_string(),
        criteria: str_of(&p, "criteria").map(str::to_string),
        image,
        repeatable: kind == BadgeKind::Kudos || bool_of(&p, "repeatable").unwrap_or(false),
        requestable,
        listed: bool_of(&p, "listed").unwrap_or(true),
        // The outside regime (VTI-BDG-062): a long-lived credential with a status in the
        // community's own set. A kudos badge was refused the setting above.
        shareable_outside: bool_of(&p, "shareableOutside").unwrap_or(false),
        group_id: None,
        state: BadgeState::Active,
        created_at: now,
        created_by: Some(entry_id),
        updated_at: now,
        retired_at: None,
    };
    // Item 6: the group first, remote steps before the one local write.
    let group = if kind == BadgeKind::Community {
        let show_members = str_of(&p, "holdersVisibleTo")
            .and_then(groups::Audience::parse)
            .unwrap_or(groups::Audience::Members);
        let spec = GroupSpec {
            name: badge.name.clone(),
            requestable,
            show_members,
            rule: automatic.clone(),
        };
        match create_group(
            state,
            &who,
            &badge.badge_id,
            &spec,
            (
                CREATE_ERR_NO_KEY_HOLDER,
                CREATE_ERR_KEY_HOLDER_UNAVAILABLE,
                CREATE_ERR_KEY_HOLDER_REFUSED,
            ),
        )
        .await
        {
            Ok(g) => Some(g),
            Err(refuse) => return refuse(&doc),
        }
    } else {
        None
    };
    badge.group_id = group.as_ref().map(|g| g.group_id.clone());
    // Item 8, then item 7: never stored unaudited.
    let mut data = changed(&badge.badge_id, "created");
    data.group_id = badge.group_id.clone();
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Some(g) = &group
        && let Err(e) = groups::put(state.directory.ks(), g).await
    {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_badge(&state.badges_ks, &badge).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Some(g) = &group {
        if let Err(e) = appoint_owners(state, &who, &g.group_id, &owners, reason_of(&doc)).await {
            return app_error_to_reject(&doc, &e);
        }
        if g.kind == groups::GroupKind::Dynamic {
            groups::dynamic::kick();
        }
    }
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut body = json!({});
    match view.badge_wire(state, &badge).await {
        Ok(b) => body["badge"] = b,
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if let Some(g) = &group {
        match groups::wire(state, g, &view.who).await {
            Ok(w) => body["group"] = w,
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    // Its group is published as an issuer the community recognises (VTI-BDG-080).
    badges::registry::kick();
    success_response(&doc, body)
}

/// `update/0.1`.
async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let settings = match settings_on(state, &doc, UPDATE_ERR_BADGES_OFF).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<badge_update::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge_id = str_of(&p, "badgeId").unwrap_or_default();
    let _guard = badges::WRITE_LOCK.lock().await;
    let mut badge = match view.visible(state, badge_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&doc, "badge"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let may = match badge.kind {
        BadgeKind::Community => view.admin || view.owns(&badge),
        BadgeKind::Kudos => view.admin || view.made(&badge),
    };
    if !may {
        return denied(&doc, "you neither administer badges nor own this one");
    }
    if !badge.is_active() {
        return declared(&doc, UPDATE_ERR_BADGE_RETIRED, "This badge is retired.");
    }
    let invalid = |doc: &TrustTask<Value>, field: &str, why: &str| {
        declared_with(
            doc,
            UPDATE_ERR_SETTINGS_INVALID,
            why,
            json!({ "field": field, "reason": why }),
        )
    };
    for k in ["kind", "repeatable", "shareableOutside", "automatic"] {
        if p.get(k).is_some() {
            return invalid(&doc, k, "Fixed at creation.");
        }
    }
    if badge.kind == BadgeKind::Kudos {
        for k in ["requestable", "holdersVisibleTo"] {
            if p.get(k).is_some() {
                return invalid(&doc, k, "A kudos badge takes no such setting.");
            }
        }
    }
    let mut fields = Vec::new();
    if let Some(n) = str_of(&p, "name") {
        badge.name = n.to_string();
        fields.push("name".to_string());
    }
    if let Some(d) = str_of(&p, "description") {
        badge.description = d.to_string();
        fields.push("description".to_string());
    }
    if let Some(c) = str_of(&p, "criteria") {
        badge.criteria = Some(c.to_string());
        fields.push("criteria".to_string());
    }
    if let Some(l) = bool_of(&p, "listed") {
        badge.listed = l;
        fields.push("listed".to_string());
    }
    if p.get("image").is_some() {
        match uploaded_image(state, &view.who, view.admin, &p, Some(&badge.badge_id)).await {
            Ok(Some(i)) => {
                badge.image = i;
                fields.push("image".to_string());
            }
            Ok(None) => {
                return declared(
                    &doc,
                    UPDATE_ERR_IMAGE_NOT_FOUND,
                    "A digest is accepted only from your own upload that no other badge holds.",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    let mut group = match &badge.group_id {
        Some(g) => match groups::get(state.directory.ks(), g).await {
            Ok(g) => g,
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => None,
    };
    if let Some(r) = bool_of(&p, "requestable") {
        if r && !settings.members_may_request {
            return invalid(
                &doc,
                "requestable",
                "This community does not let members ask for badges.",
            );
        }
        if let Some(g) = group.as_mut() {
            if g.kind == groups::GroupKind::Dynamic && r {
                return invalid(
                    &doc,
                    "requestable",
                    "An automatic badge is never asked for.",
                );
            }
            g.join_policy = if r {
                groups::JoinPolicy::Request
            } else {
                groups::JoinPolicy::Closed
            };
        }
        badge.requestable = r;
        fields.push("requestable".to_string());
    }
    if let Some(a) = str_of(&p, "holdersVisibleTo") {
        let Some(a) = groups::Audience::parse(a) else {
            return invalid(&doc, "holdersVisibleTo", "Not an audience.");
        };
        if let Some(g) = group.as_mut() {
            g.show_members = a;
        }
        fields.push("holdersVisibleTo".to_string());
    }
    let now = Utc::now();
    badge.updated_at = now;
    let mut data = changed(&badge.badge_id, "updated");
    data.fields = fields;
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Some(mut g) = group {
        g.name = badge.name.clone();
        g.updated_at = now;
        if let Err(e) = groups::put(state.directory.ks(), &g).await {
            return app_error_to_reject(&doc, &e);
        }
    }
    if let Err(e) = badges::put_badge(&state.badges_ks, &badge).await {
        return app_error_to_reject(&doc, &e);
    }
    match view.badge_wire(state, &badge).await {
        Ok(b) => success_response(&doc, json!({ "badge": b })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Delete `group` as `vtc/groups/delete` does for a badge group: its authority revoked,
/// its managers withdrawn, its memberships removed. It carries no authority, so nothing
/// is provisioned.
async fn delete_group(state: &AppState, group: &Group) -> Result<(), AppError> {
    if let Some(a) = &group.authority {
        identity::revoke_authority(state, a).await?;
    }
    groups::managers::withdraw_all(state, &group.group_id).await?;
    groups::remove(state.directory.ks(), &group.group_id).await?;
    Ok(())
}

/// `retire/0.1` (VTI-BDG-005).
async fn handle_retire(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, RETIRE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<badge_retire::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge_id = str_of(&p, "badgeId").unwrap_or_default();
    let mut badge = match view.visible(state, badge_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&doc, "badge"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let may = match badge.kind {
        BadgeKind::Community => view.admin,
        BadgeKind::Kudos => view.admin || view.made(&badge),
    };
    if !may {
        return denied(&doc, "retiring this badge takes vtc.badges.admin");
    }
    let group = match &badge.group_id {
        Some(g) => match groups::get(state.directory.ks(), g).await {
            Ok(g) => g,
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => None,
    };
    if !badge.is_active() && group.is_none() {
        return declared(
            &doc,
            RETIRE_ERR_ALREADY_RETIRED,
            "This badge is already retired.",
        );
    }
    if badge.kind == BadgeKind::Community
        && let Err(r) = bound_step_up(
            state,
            &view.who.did,
            &doc,
            &format!("Retire the badge “{}”", badge.name),
        )
        .await
    {
        return r;
    }
    let now = Utc::now();
    let mut data = changed(&badge.badge_id, "retired");
    data.group_id = badge.group_id.clone();
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if badge.is_active() {
        badge.state = BadgeState::Retired;
        badge.retired_at = Some(now);
        badge.updated_at = now;
        if let Err(e) = badges::put_badge(&state.badges_ks, &badge).await {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = badges::withdraw_open_offers(&state.badges_ks, &badge.badge_id, now).await {
            return app_error_to_reject(&doc, &e);
        }
    }
    // A retired badge's claim codes admit no one (VTI-BDG-027).
    if let Err(e) = badges::claims::withdraw_all_of_badge(&state.badges_ks, &badge.badge_id).await {
        return app_error_to_reject(&doc, &e);
    }
    // A retired badge is shown outside no longer (`share` item 9); also on a retry.
    if let Err(e) = badges::share::stop_all_of_badge(&state.badges_ks, &badge.badge_id).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Some(g) = &group
        && let Err(e) = delete_group(state, g).await
    {
        return match e {
            AppError::ServiceError { .. } => declared(
                &doc,
                RETIRE_ERR_KEY_HOLDER_UNAVAILABLE,
                "The badge is retired; its group's authority is revoked when the community's \
                 status list can be written. Send the request again.",
            ),
            e => app_error_to_reject(&doc, &e),
        };
    }
    // Every holder's credential that carries a status is revoked with the badge
    // (VTI-BDG-063); the group's one bit already covers what chains to its authority.
    if let Err(e) = badges::credential::revoke_all_holders(state, &badge.badge_id).await {
        return app_error_to_reject(&doc, &e);
    }
    // Its record goes from the trust registry (VTI-BDG-080).
    badges::registry::kick();
    let _ = RETIRE_ERR_KEY_HOLDER_REFUSED;
    match view.badge_wire(state, &badge).await {
        Ok(b) => success_response(&doc, json!({ "badge": b })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `promote/0.1` (VTI-BDG-044).
async fn handle_promote(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let settings = match settings_on(state, &doc, PROMOTE_ERR_BADGES_OFF).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<badge_promote::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !view.admin {
        return denied(&doc, "promoting a badge takes vtc.badges.admin");
    }
    let badge_id = str_of(&p, "badgeId").unwrap_or_default();
    let mut badge = match view.visible(state, badge_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&doc, "badge"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if badge.kind == BadgeKind::Community {
        return declared(
            &doc,
            PROMOTE_ERR_KIND_MISMATCH,
            "This is already a community badge.",
        );
    }
    if !badge.is_active() {
        return declared(&doc, PROMOTE_ERR_BADGE_RETIRED, "This badge is retired.");
    }
    let requestable = bool_of(&p, "requestable").unwrap_or(false);
    if requestable && !settings.members_may_request {
        return declared_with(
            &doc,
            PROMOTE_ERR_SETTINGS_INVALID,
            "This community does not let members ask for badges.",
            json!({ "field": "requestable" }),
        );
    }
    let owners = string_list(&p, "owners").unwrap_or_default();
    if !owners.is_empty() && !view.who.manages_all {
        return declared(
            &doc,
            PROMOTE_ERR_OWNER_NOT_ELIGIBLE,
            "Appointing owners takes vtc.groups.manage at the community.",
        );
    }
    match owners_eligible(state, &owners).await {
        Ok(None) => {}
        Ok(Some(e)) => {
            return declared_with(
                &doc,
                PROMOTE_ERR_OWNER_NOT_ELIGIBLE,
                "An owner named is not an active member.",
                json!({ "entryId": e }),
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let spec = GroupSpec {
        name: badge.name.clone(),
        requestable,
        show_members: str_of(&p, "holdersVisibleTo")
            .and_then(groups::Audience::parse)
            .unwrap_or(groups::Audience::Members),
        rule: None,
    };
    let group = match create_group(
        state,
        &view.who,
        &badge.badge_id,
        &spec,
        (
            PROMOTE_ERR_NO_KEY_HOLDER,
            PROMOTE_ERR_KEY_HOLDER_UNAVAILABLE,
            PROMOTE_ERR_KEY_HOLDER_REFUSED,
        ),
    )
    .await
    {
        Ok(g) => g,
        Err(refuse) => return refuse(&doc),
    };
    let now = Utc::now();
    let mut data = changed(&badge.badge_id, "promoted");
    data.group_id = Some(group.group_id.clone());
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = groups::put(state.directory.ks(), &group).await {
        return app_error_to_reject(&doc, &e);
    }
    badge.kind = BadgeKind::Community;
    badge.group_id = Some(group.group_id.clone());
    badge.requestable = requestable;
    badge.shareable_outside = bool_of(&p, "shareableOutside").unwrap_or(false);
    badge.updated_at = now;
    if let Err(e) = badges::put_badge(&state.badges_ks, &badge).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) =
        appoint_owners(state, &view.who, &group.group_id, &owners, reason_of(&doc)).await
    {
        return app_error_to_reject(&doc, &e);
    }
    // Every current holder is offered the community badge (nothing issued until they
    // accept); their kudos awards stay as history.
    let holders = match badges::shown_holders(&state.badges_ks, &badge.badge_id).await {
        Ok(h) => h,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut offered = 0;
    let giver = view.entry_id.clone();
    for (entry_id, _) in holders {
        let a = Award {
            award_id: badges::new_award_id(),
            badge_id: badge.badge_id.clone(),
            entry_id,
            given_by: giver.clone(),
            note: Some("Promoted to a community badge".into()),
            state: AwardState::Offered,
            offered_at: now,
            decided_at: None,
            expires_at: settings
                .limits
                .offer_expires_after_days
                .map(|d| now + Duration::days(i64::from(d))),
            credential_id: None,
            revoke_reason: None,
            shared: None,
        };
        if let Err(e) = badges::put_award(&state.badges_ks, &a).await {
            return app_error_to_reject(&doc, &e);
        }
        offered += 1;
    }
    let mut body = json!({ "holdersOffered": offered });
    match view.badge_wire(state, &badge).await {
        Ok(b) => body["badge"] = b,
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match groups::wire(state, &group, &view.who).await {
        Ok(w) => body["group"] = w,
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Its group is published as an issuer the community recognises (VTI-BDG-080).
    badges::registry::kick();
    success_response(&doc, body)
}

/// `list/0.1`.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if !who.may_read() {
        return denied(
            &doc,
            "badges are read by this community's active members and administrators",
        );
    }
    if let Err(r) = parse_spec_payload::<badge_list::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let include_unlisted = bool_of(&p, "includeUnlisted").unwrap_or(false);
    let include_retired = bool_of(&p, "includeRetired").unwrap_or(false);
    if (include_unlisted || include_retired) && !view.admin {
        return denied(
            &doc,
            "listing unlisted or retired badges takes vtc.badges.admin",
        );
    }
    let kind = str_of(&p, "kind").and_then(BadgeKind::parse);
    let mine = bool_of(&p, "mine").unwrap_or(false);
    let all = match badges::all_badges(&state.badges_ks).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let chosen: Vec<Badge> = all
        .into_iter()
        .filter(|b| view.sees(b))
        .filter(|b| b.is_active() || include_retired)
        // An administrator sees unlisted badges only when asked; a member sees one they
        // hold, own or made as the visibility rule admits.
        .filter(|b| {
            b.listed
                || !view.admin
                || include_unlisted
                || view.holds(&b.badge_id)
                || view.owns(b)
                || view.made(b)
        })
        .filter(|b| kind.is_none_or(|k| b.kind == k))
        .filter(|b| !mine || view.holds(&b.badge_id))
        .collect();
    let binding = format!(
        "badges/list|{}|{}|{mine}|{include_unlisted}|{include_retired}",
        view.who.did,
        kind.map_or("", BadgeKind::as_str)
    );
    let offset = match offset_of(&p, &binding) {
        Ok(o) => o,
        Err(()) => {
            return declared(
                &doc,
                LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for these filters.",
            );
        }
    };
    let (items, next) = page(&chosen, offset, limit_of(&p), &binding);
    let mut out = Vec::with_capacity(items.len());
    for b in &items {
        let wire = match view.badge_wire(state, b).await {
            Ok(w) => w,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let my_state = match view.my_state(state, b).await {
            Ok(s) => s,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        out.push(json!({
            "badge": wire,
            "myCount": view.my_count(&b.badge_id),
            "myState": my_state,
        }));
    }
    let mut body = json!({ "items": out });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

/// `show/0.1`.
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<badge_show::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match view
        .visible(state, str_of(&p, "badgeId").unwrap_or_default())
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&doc, "badge"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut body = json!({
        "myCount": view.my_count(&badge.badge_id),
        "credentialRegime": match (&badge.kind, badge.shareable_outside) {
            (BadgeKind::Kudos, _) => "none",
            (BadgeKind::Community, true) => "outside",
            (BadgeKind::Community, false) => "inside",
        },
    });
    match view.badge_wire(state, &badge).await {
        Ok(w) => body["badge"] = w,
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    match view.my_state(state, &badge).await {
        Ok(s) => body["myState"] = json!(s),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Item 4: the caller's own accepted awards, newest first, each with its share — what
    // `awards/share` and `unshare` name. Never another member's.
    if view.my_count(&badge.badge_id) > 0
        && let Some(entry) = &view.entry_id
    {
        match badges::accepted_of(&state.badges_ks, &badge.badge_id, entry).await {
            Ok(mut mine) if !mine.is_empty() => {
                mine.sort_by_key(|a| std::cmp::Reverse(a.decided_at));
                body["myAwards"] = json!(mine.iter().map(|a| a.wire(true)).collect::<Vec<_>>());
            }
            Ok(_) => {}
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    match &badge.group_id {
        Some(g) => match groups::managers(state, g).await {
            Ok(m) => body["owners"] = json!(m),
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => {
            if let Some(m) = &badge.created_by {
                body["maker"] = json!(m);
            }
        }
    }
    success_response(&doc, body)
}

// ─── pictures ────────────────────────────────────────────────────────────

/// `images/upload/0.1`: mirrors the directory's, over the badges' own picture store.
async fn handle_images_upload(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if ctx.verified_signer.is_none() {
        return reject_with(&doc, RejectReason::ProofRequired);
    }
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(_) => {
            return declared(
                &doc,
                UPLOAD_ERR_NOT_MEMBER,
                "the signer is neither an active member nor a badge administrator",
            );
        }
    };
    let delegated_key = ctx.verified_signer.as_deref().is_some_and(|s| s != who.did);
    let admin = !delegated_key && who.can(Capability::BadgesAdmin);
    if !who.active_member && !admin {
        return declared(
            &doc,
            UPLOAD_ERR_NOT_MEMBER,
            "the signer is neither an active member nor a badge administrator",
        );
    }
    if let Err(r) = settings_on(state, &doc, UPLOAD_ERR_BADGES_OFF).await {
        return r;
    }
    let payload = match parse_spec_payload::<images_upload::Payload>(&doc) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !state.directory.admit_upload(&who.did) {
        return declared(
            &doc,
            UPLOAD_ERR_RATE_LIMITED,
            "too many pictures uploaded in the last hour; try again later",
        );
    }
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.data.as_str())
    else {
        return declared(&doc, UPLOAD_ERR_NOT_AN_IMAGE, "`data` is not base64url");
    };
    if bytes.len() > images::MAX_IMAGE_BYTES {
        return declared(
            &doc,
            UPLOAD_ERR_TOO_LARGE,
            format!(
                "a picture is at most {} bytes; nothing was stored",
                images::MAX_IMAGE_BYTES
            ),
        );
    }
    let media_type = payload.media_type.to_string();
    let encoded =
        match tokio::task::spawn_blocking(move || images::reencode(&bytes, &media_type)).await {
            Ok(Ok(e)) => e,
            Ok(Err(UploadError::TooLarge)) => {
                return declared(
                    &doc,
                    UPLOAD_ERR_TOO_LARGE,
                    "the picture claims more pixels than this community decodes",
                );
            }
            Ok(Err(UploadError::NotAnImage)) => {
                return declared(
                    &doc,
                    UPLOAD_ERR_NOT_AN_IMAGE,
                    "`data` does not decode as an image of `mediaType`",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &AppError::Internal(e.to_string())),
        };
    let owner = if admin {
        Owner::Admins
    } else {
        match own_entry(state, &who).await {
            Ok(e) => Owner::Member(e),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    };
    let now = Utc::now();
    let (image, expires_at) =
        match images::store(&state.badge_images_ks, &owner, &encoded, now).await {
            Ok(x) => x,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
    // An administrator's upload is also theirs as a member, so either `create` reads it.
    if admin && let Some(e) = &who.entry_id {
        let _ = images::store(
            &state.badge_images_ks,
            &Owner::Member(e.clone()),
            &encoded,
            now,
        )
        .await;
    }
    let mut data = changed("-", "imageUploaded");
    data.fields = vec![format!("sha256:{}", encoded.sha256())];
    if let Err(e) = audit(state, &who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "image": image, "expiresAt": expires_at }))
}

/// `images/get/0.1`.
async fn handle_images_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<images_get::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match view
        .visible(state, str_of(&p, "badgeId").unwrap_or_default())
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                GET_ERR_NOT_FOUND,
                "No badge you may see holds this picture.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let Some(sha) = images::sha_of(&badge.image) else {
        return declared(
            &doc,
            GET_ERR_NOT_FOUND,
            "No badge you may see holds this picture.",
        );
    };
    if let Some(expected) = str_of(&p, "sha256")
        && expected != sha
    {
        return declared(
            &doc,
            GET_ERR_NOT_FOUND,
            "The badge now holds another picture.",
        );
    }
    match images::get(&state.badge_images_ks, sha).await {
        Ok(Some((stored, bytes))) => success_response(
            &doc,
            json!({
                "image": { "sha256": sha, "mediaType": stored.media_type, "size": stored.size },
                "data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
            }),
        ),
        Ok(None) => declared(
            &doc,
            GET_ERR_NOT_FOUND,
            "No badge you may see holds this picture.",
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── awards: the owners' side ────────────────────────────────────────────

/// The badge an owner acts on (`awards/*`): `notFound` where the caller may not see it,
/// `permissionDenied` where they may but do not own it.
async fn owned_badge(
    state: &AppState,
    doc: &TrustTask<Value>,
    view: &View,
    badge_id: &str,
    not_found_code: Option<&str>,
) -> Result<Badge, TrustTaskOutcome> {
    let badge = view
        .visible(state, badge_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    match badge {
        Some(b) if view.admin || view.owns(&b) => Ok(b),
        Some(_) => Err(denied(doc, "you do not own this badge")),
        None => Err(match not_found_code {
            Some(c) => declared(doc, c, "No badge you may act on has this identifier."),
            None => not_found(doc, "badge"),
        }),
    }
}

/// `awards/offer/0.1` (items 1 – 7).
async fn handle_offer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let settings = match settings_on(state, &doc, OFFER_ERR_BADGES_OFF).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<awards_offer::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match owned_badge(
        state,
        &doc,
        &view,
        str_of(&p, "badgeId").unwrap_or_default(),
        None,
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    if badge.kind == BadgeKind::Kudos {
        return declared(
            &doc,
            OFFER_ERR_KIND_MISMATCH,
            format!(
                "{} is a kudos badge: give it with vtc/badges/kudos/give.",
                badge.name
            ),
        );
    }
    if !badge.is_active() {
        return declared(&doc, OFFER_ERR_BADGE_RETIRED, "This badge is retired.");
    }
    let group = match &badge.group_id {
        Some(g) => match groups::get(state.directory.ks(), g).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                return declared(&doc, OFFER_ERR_BADGE_RETIRED, "This badge's group is gone.");
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => return declared(&doc, OFFER_ERR_BADGE_RETIRED, "This badge has no group."),
    };
    if group.kind == groups::GroupKind::Dynamic {
        return declared(
            &doc,
            OFFER_ERR_AUTOMATIC_BADGE,
            "This badge is automatic: its rule gives it.",
        );
    }
    // Item 3: the recipients, resolved once, now.
    let recipients: Vec<String> = if let Some(to) = string_list(&p, "to") {
        to
    } else if let Some(gid) = str_of(&p, "group") {
        match groups::get(state.directory.ks(), gid).await {
            Ok(Some(g)) if view.who.sees_members(&g) => {
                match groups::members_of(state.directory.ks(), gid).await {
                    Ok(m) => m
                        .into_iter()
                        .filter(|m| m.state == "active")
                        .map(|m| m.entry_id)
                        .collect(),
                    Err(e) => return app_error_to_reject(&doc, &e),
                }
            }
            Ok(_) => {
                return declared(
                    &doc,
                    OFFER_ERR_GROUP_NOT_VISIBLE,
                    "No group whose members you may see has this identifier.",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    } else {
        Vec::new()
    };
    let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let now = Utc::now();
    let _guard = badges::WRITE_LOCK.lock().await;
    let existing = match badges::awards_of_badge(&state.badges_ks, &badge.badge_id).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut awards = Vec::new();
    let mut skipped = Vec::new();
    for entry_id in recipients {
        let skip = |reason: &str| json!({ "entryId": entry_id, "reason": reason });
        let active = match active_entry(state, &entry_id).await {
            Ok(d) => d,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let shown = directory_shows(state, &viewer, &entry_id).await;
        if active.is_none() || !(shown || view.admin) {
            skipped.push(skip("notActiveMember"));
            continue;
        }
        if existing
            .iter()
            .any(|a| a.entry_id == entry_id && a.is_open())
        {
            skipped.push(skip("alreadyOffered"));
            continue;
        }
        if !badge.repeatable
            && existing
                .iter()
                .any(|a| a.entry_id == entry_id && a.is_accepted())
        {
            skipped.push(skip("alreadyHolder"));
            continue;
        }
        match groups::pending_request(state.directory.ks(), &group.group_id, &entry_id).await {
            Ok(Some(_)) => {
                skipped.push(skip("requestPending"));
                continue;
            }
            Ok(None) => {}
            Err(e) => return app_error_to_reject(&doc, &e),
        }
        let a = Award {
            award_id: badges::new_award_id(),
            badge_id: badge.badge_id.clone(),
            entry_id: entry_id.clone(),
            given_by: view.entry_id.clone(),
            note: str_of(&p, "note").map(str::to_string),
            state: AwardState::Offered,
            offered_at: now,
            decided_at: None,
            expires_at: settings
                .limits
                .offer_expires_after_days
                .map(|d| now + Duration::days(i64::from(d))),
            credential_id: None,
            revoke_reason: None,
            shared: None,
        };
        awards.push(a);
    }
    if awards.is_empty() {
        return declared_with(
            &doc,
            OFFER_ERR_NOTHING_TO_OFFER,
            "Every recipient was skipped.",
            json!({ "skipped": skipped }),
        );
    }
    for a in &awards {
        if let Err(e) = audit(state, &view.who.did, award_changed(a, "offered")).await {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = badges::put_award(&state.badges_ks, a).await {
            return app_error_to_reject(&doc, &e);
        }
    }
    success_response(
        &doc,
        json!({
            "awards": awards.iter().map(|a| a.wire(true)).collect::<Vec<_>>(),
            "skipped": skipped,
        }),
    )
}

/// `awards/withdraw/0.1`.
async fn handle_withdraw(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // The giver of a kudos award withdraws it as a member (delegated key accepted);
    // an owner withdraws with their own key. Read permissively, then check.
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, WITHDRAW_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<awards_withdraw::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let delegated = ctx.verified_signer.as_deref().is_some_and(|s| s != who.did);
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let _guard = badges::WRITE_LOCK.lock().await;
    let mut award = match badges::get_award(
        &state.badges_ks,
        str_of(&p, "awardId").unwrap_or_default(),
    )
    .await
    {
        Ok(Some(a)) => a,
        Ok(None) => {
            return declared(
                &doc,
                WITHDRAW_ERR_NOT_FOUND,
                "No award you may withdraw has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match view.visible(state, &award.badge_id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                WITHDRAW_ERR_NOT_FOUND,
                "No award you may withdraw has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let giver = award.given_by.is_some() && award.given_by == view.entry_id;
    let owner = !delegated && (view.admin || view.owns(&badge));
    let may = match badge.kind {
        BadgeKind::Kudos => giver || owner,
        BadgeKind::Community => owner,
    };
    if !may {
        return declared(
            &doc,
            WITHDRAW_ERR_NOT_FOUND,
            "No award you may withdraw has this identifier.",
        );
    }
    if !award.is_open() {
        return declared_with(
            &doc,
            WITHDRAW_ERR_ALREADY_DECIDED,
            "This award is no longer an open offer.",
            json!({ "state": award.state.as_str() }),
        );
    }
    award.state = AwardState::Withdrawn;
    award.decided_at = Some(Utc::now());
    if let Err(e) = audit(state, &view.who.did, award_changed(&award, "withdrawn")).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_award(&state.badges_ks, &award).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "award": award.wire(true) }))
}

/// Re-issue the holder's badge credential with their remaining awards, or end their
/// membership where none remain (revoke items 3 – 5).
async fn settle_after_revoke(
    state: &AppState,
    badge: &Badge,
    entry_id: &str,
) -> Result<Result<(), Failure>, AppError> {
    let Some(gid) = &badge.group_id else {
        return Ok(Ok(()));
    };
    let Some(group) = groups::get(state.directory.ks(), gid).await? else {
        return Ok(Ok(()));
    };
    let remaining = badges::accepted_of(&state.badges_ks, &badge.badge_id, entry_id).await?;
    let Some(did) = active_entry(state, entry_id).await? else {
        // Their last credential is revoked where it carries a status (VTI-BDG-063).
        badges::credential::revoke_holder(state, &badge.badge_id, entry_id).await?;
        groups::remove_membership(state.directory.ks(), gid, entry_id).await?;
        return Ok(Ok(()));
    };
    if remaining.is_empty() {
        badges::credential::revoke_holder(state, &badge.badge_id, entry_id).await?;
        groups::remove_membership(state.directory.ks(), gid, entry_id).await?;
        return Ok(Ok(()));
    }
    reissue(state, &group, badge, &did, entry_id, remaining).await
}

/// Issue `did` their credential of `badge` again over `awards` (the accepted ones), offer
/// it, and record it on the membership and the awards — credential first, as ever.
async fn reissue(
    state: &AppState,
    group: &Group,
    badge: &Badge,
    did: &str,
    entry_id: &str,
    awards: Vec<Award>,
) -> Result<Result<(), Failure>, AppError> {
    match badges::credential::issue(state, group, badge, did, Some(entry_id), &awards).await {
        Ok(issued) => {
            badges::credential::offer(state, group, did, &issued).await;
            let ks = state.directory.ks();
            if let Some(mut m) = groups::membership(ks, &group.group_id, entry_id).await? {
                m.credential_id = Some(issued.credential_id.clone());
                m.credential_valid_until = Some(issued.valid_until);
                groups::put_membership(ks, &m).await?;
            }
            let _guard = badges::WRITE_LOCK.lock().await;
            for a in awards {
                // Re-read: only the record as it stands now is moved on.
                if let Some(mut a) = badges::get_award(&state.badges_ks, &a.award_id).await?
                    && a.is_accepted()
                {
                    a.credential_id = Some(issued.credential_id.clone());
                    badges::put_award(&state.badges_ks, &a).await?;
                }
            }
            Ok(Ok(()))
        }
        Err(f) => Ok(Err(f)),
    }
}

/// `awards/revoke/0.1` (VTI-BDG-023).
async fn handle_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, REVOKE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<awards_revoke::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut award = {
        let _guard = badges::WRITE_LOCK.lock().await;
        let award =
            match badges::get_award(&state.badges_ks, str_of(&p, "awardId").unwrap_or_default())
                .await
            {
                Ok(Some(a)) => a,
                Ok(None) => {
                    return declared(
                        &doc,
                        REVOKE_ERR_NOT_FOUND,
                        "No award you may take back has this identifier.",
                    );
                }
                Err(e) => return app_error_to_reject(&doc, &e),
            };
        let badge = match owned_badge(
            state,
            &doc,
            &view,
            &award.badge_id,
            Some(REVOKE_ERR_NOT_FOUND),
        )
        .await
        {
            Ok(b) => b,
            Err(r) => return r,
        };
        if !award.is_accepted() {
            return declared_with(
                &doc,
                REVOKE_ERR_NOT_ACCEPTED,
                "Only an accepted award is taken back.",
                json!({ "state": award.state.as_str() }),
            );
        }
        let mut award = award;
        award.state = AwardState::Revoked;
        award.decided_at = Some(Utc::now());
        award.revoke_reason = reason_of(&doc);
        // A taken-back award is shown outside no longer (`share` item 9).
        if let Err(e) = badges::share::forget(&state.badges_ks, &mut award).await {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = audit(state, &view.who.did, award_changed(&award, "revoked")).await {
            return app_error_to_reject(&doc, &e);
        }
        if let Err(e) = badges::put_award(&state.badges_ks, &award).await {
            return app_error_to_reject(&doc, &e);
        }
        (award, badge)
    };
    let (award, badge) = (&mut award.0, award.1);
    match settle_after_revoke(state, &badge, &award.entry_id).await {
        Ok(Ok(())) => {}
        Ok(Err(f)) => {
            return failure_refusal(
                &doc,
                f,
                REVOKE_ERR_KEY_HOLDER_UNAVAILABLE,
                REVOKE_ERR_KEY_HOLDER_REFUSED,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    success_response(&doc, json!({ "award": award.wire(true) }))
}

/// `awards/share/0.1` (VTI-BDG-070): the holder starts showing one accepted award outside
/// the community, at locations under the community's public origin.
async fn handle_share(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, SHARE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<awards_share::Payload>(&doc) {
        return r;
    }
    let award_id = str_of(&doc.payload, "awardId").unwrap_or_default();
    let public_url = state.config.read().await.public_url.clone();
    let guard = badges::WRITE_LOCK.lock().await;
    // Item 2: unknown, another's and not accepted answer alike.
    let award = match badges::get_award(&state.badges_ks, award_id).await {
        Ok(Some(a)) if a.entry_id == entry_id && a.is_accepted() => a,
        Ok(_) => {
            return declared(
                &doc,
                SHARE_ERR_NOT_FOUND,
                "No accepted award of yours has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 3: the badge's regime, fixed when it was defined.
    let badge = match badges::get_badge(&state.badges_ks, &award.badge_id).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let reason = match &badge {
        Some(b) if !b.is_community() => Some("kudos"),
        Some(b) if !b.is_active() => Some("retired"),
        None => Some("retired"),
        Some(b) if !b.shareable_outside => Some("insideOnly"),
        Some(_) => None,
    };
    if let Some(reason) = reason {
        return declared_with(
            &doc,
            SHARE_ERR_NOT_SHAREABLE,
            match reason {
                "kudos" => "A kudos badge is shown inside the community only.",
                "retired" => "This badge was retired.",
                _ => "This badge is shown inside the community only.",
            },
            json!({ "reason": reason }),
        );
    }
    // Item 4: never answer a location it will not serve.
    let Some(public_url) = public_url.filter(|u| !u.trim().is_empty()) else {
        return declared(
            &doc,
            SHARE_ERR_PUBLIC_LOCATION_UNAVAILABLE,
            "This community has no public address to show a badge at yet.",
        );
    };
    // The credential the share serves (item 5) is kept whenever one is issued in the
    // outside regime. A holder whose credential predates that is issued it again first —
    // the same credential in the same regime and slot, outside the lock as every issue is.
    let kept =
        match badges::share::kept_credential(&state.badges_ks, &award.badge_id, &entry_id).await {
            Ok(k) => k.is_some(),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
    let mut award = award;
    if !kept {
        drop(guard);
        let badge = badge.expect("checked above");
        if let Err(r) = issue_to_share(state, &doc, &badge, &view.who.did, &entry_id).await {
            return r;
        }
        let _guard = badges::WRITE_LOCK.lock().await;
        award = match badges::get_award(&state.badges_ks, award_id).await {
            Ok(Some(a)) if a.entry_id == entry_id && a.is_accepted() => a,
            Ok(_) => {
                return declared(
                    &doc,
                    SHARE_ERR_NOT_FOUND,
                    "No accepted award of yours has this identifier.",
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        return share_award(state, &doc, &view, award, &public_url).await;
    }
    share_award(state, &doc, &view, award, &public_url).await
}

/// Issue the holder their badge credential again, for a share whose credential predates
/// the community keeping one. A key holder that cannot sign is the framework's own
/// "unavailable": the share declares no key-holder code, and nothing was recorded.
async fn issue_to_share(
    state: &AppState,
    doc: &TrustTask<Value>,
    badge: &Badge,
    did: &str,
    entry_id: &str,
) -> Result<(), TrustTaskOutcome> {
    let group = match &badge.group_id {
        Some(g) => groups::get(state.directory.ks(), g)
            .await
            .map_err(|e| app_error_to_reject(doc, &e))?,
        None => None,
    };
    let Some(group) = group else {
        return Err(declared(
            doc,
            SHARE_ERR_NOT_SHAREABLE,
            "This badge was retired.",
        ));
    };
    let awards = badges::accepted_of(&state.badges_ks, &badge.badge_id, entry_id)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    match reissue(state, &group, badge, did, entry_id, awards).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(f)) => {
            tracing::warn!(badge = %badge.badge_id, error = ?f, "could not issue a badge credential to share");
            Err(app_error_to_reject(
                doc,
                &AppError::Internal(
                    "the community's key holder could not issue the credential to share; \
                     try again shortly"
                        .into(),
                ),
            ))
        }
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// Items 5 and 8: start sharing `award` (a share already in force answers its own
/// locations), audit a new one, and answer the award. The caller holds the write lock.
async fn share_award(
    state: &AppState,
    doc: &TrustTask<Value>,
    view: &View,
    mut award: Award,
    public_url: &str,
) -> TrustTaskOutcome {
    let doc = doc.clone();
    let started = match badges::share::start(&state.badges_ks, &mut award, public_url).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if started && let Err(e) = audit(state, &view.who.did, award_changed(&award, "shared")).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "award": award.wire(true) }))
}

/// `awards/unshare/0.1` (VTI-BDG-070): the holder stops showing an award outside. Revokes
/// nothing.
async fn handle_unshare(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, UNSHARE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<awards_unshare::Payload>(&doc) {
        return r;
    }
    let award_id = str_of(&doc.payload, "awardId").unwrap_or_default();
    let _guard = badges::WRITE_LOCK.lock().await;
    let mut award = match badges::get_award(&state.badges_ks, award_id).await {
        Ok(Some(a)) if a.entry_id == entry_id => a,
        Ok(_) => {
            return declared(
                &doc,
                UNSHARE_ERR_NOT_FOUND,
                "No award of yours has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    match badges::share::stop(&state.badges_ks, &mut award).await {
        Ok(true) => {
            if let Err(e) = audit(state, &view.who.did, award_changed(&award, "unshared")).await {
                return app_error_to_reject(&doc, &e);
            }
        }
        Ok(false) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    success_response(&doc, json!({ "award": award.wire(true) }))
}

// ─── claim codes (VTI-BDG-025 – 027) ────────────────────────────────────────

/// The badge `badge_id` names, where the caller owns it — manages its group — or
/// administers badges; `None` otherwise, which every claim task answers as `notFound`.
async fn claimable_by(
    state: &AppState,
    view: &View,
    badge_id: &str,
) -> Result<Option<Badge>, AppError> {
    Ok(view
        .visible(state, badge_id)
        .await?
        .filter(|b| view.admin || (badge_is_community(b) && view.owns(b))))
}

/// `claims/create/0.1` (VTI-BDG-025).
async fn handle_claims_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, CLAIMS_CREATE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<claims_create::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match claimable_by(state, &view, str_of(&p, "badgeId").unwrap_or_default()).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                CLAIMS_CREATE_ERR_NOT_FOUND,
                "No badge you own has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !badge.is_community() {
        return declared_with(
            &doc,
            CLAIMS_CREATE_ERR_NOT_CLAIMABLE,
            "A kudos badge is given by members one by one, never by a code.",
            json!({ "reason": "kudos" }),
        );
    }
    if !badge.is_active() {
        return declared_with(
            &doc,
            CLAIMS_CREATE_ERR_NOT_CLAIMABLE,
            "This badge was retired.",
            json!({ "reason": "retired" }),
        );
    }
    let now = Utc::now();
    let valid_until = str_of(&p, "validUntil")
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc));
    let Some(valid_until) =
        valid_until.filter(|t| *t > now && *t <= now + Duration::days(badges::claims::MAX_DAYS))
    else {
        return declared(
            &doc,
            CLAIMS_CREATE_ERR_SETTINGS_INVALID,
            "A code's time is in the future and at most 90 days ahead.",
        );
    };
    let limit = p["limit"].as_u64().unwrap_or(1).clamp(1, 10_000) as u32;
    let label = str_of(&p, "label").unwrap_or_default();
    let (rec, code) = match badges::claims::create(
        &state.badges_ks,
        &badge.badge_id,
        label,
        valid_until,
        limit,
        view.entry_id.as_deref(),
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut data = changed(&badge.badge_id, "claimCodeIssued");
    data.fields = vec![rec.claim_id.clone()];
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "claim": rec.wire(), "code": code }))
}

/// `claims/list/0.1` (VTI-BDG-027): never a code.
async fn handle_claims_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<claims_list::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let not_found = || {
        declared(
            &doc,
            CLAIMS_LIST_ERR_NOT_FOUND,
            "No badge you own has this identifier.",
        )
    };
    match badges::settings(&state.badges_ks).await {
        Ok(s) if s.enabled => {}
        Ok(_) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match claimable_by(state, &view, str_of(&p, "badgeId").unwrap_or_default()).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let all = match badges::claims::of_badge(&state.badges_ks, &badge.badge_id).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!("badges/claims/list|{}|{}", view.who.did, badge.badge_id);
    let offset = match offset_of(&p, &binding) {
        Ok(o) => o,
        Err(()) => {
            return declared(
                &doc,
                CLAIMS_LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for this badge.",
            );
        }
    };
    let (items, next) = page(&all, offset, limit_of(&p), &binding);
    let mut body = json!({ "items": items.iter().map(|c| c.wire()).collect::<Vec<_>>() });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

/// `claims/withdraw/0.1` (VTI-BDG-027): admits no one more; claims made stand.
async fn handle_claims_withdraw(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, CLAIMS_WITHDRAW_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<claims_withdraw::Payload>(&doc) {
        return r;
    }
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let claim_id = str_of(&doc.payload, "claimId").unwrap_or_default();
    let not_found = || {
        declared(
            &doc,
            CLAIMS_WITHDRAW_ERR_NOT_FOUND,
            "No claim code of a badge you own has this identifier.",
        )
    };
    let rec = match badges::claims::get(&state.badges_ks, claim_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    match claimable_by(state, &view, &rec.badge_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let rec = match badges::claims::withdraw(&state.badges_ks, claim_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut data = changed(&rec.badge_id, "claimCodeWithdrawn");
    data.fields = vec![rec.claim_id.clone()];
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "claim": rec.wire() }))
}

/// `claims/redeem/0.1` (VTI-BDG-026): the redemption is the member's consent; admitted as
/// on an approved request, with an award whose giver is the code's issuer.
async fn handle_claims_redeem(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, REDEEM_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<claims_redeem::Payload>(&doc) {
        return r;
    }
    let code = str_of(&doc.payload, "code").unwrap_or_default().to_string();
    let invalid = || declared(&doc, REDEEM_ERR_CODE_INVALID, "This code admits no one.");
    // Item 2: the code and its badge, refused alike.
    let rec = match badges::claims::by_code(&state.badges_ks, &code).await {
        Ok(Some(r)) => r,
        Ok(None) => return invalid(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match badges::get_badge(&state.badges_ks, &rec.badge_id).await {
        Ok(Some(b)) if b.is_active() && b.is_community() => b,
        Ok(_) => return invalid(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let group = match &badge.group_id {
        Some(g) => match groups::get(state.directory.ks(), g).await {
            Ok(Some(g)) => g,
            Ok(None) => return invalid(),
            Err(e) => return app_error_to_reject(&doc, &e),
        },
        None => return invalid(),
    };
    // Item 3: a one-off badge already held.
    if !badge.repeatable && view.my_count(&badge.badge_id) > 0 {
        return declared(
            &doc,
            REDEEM_ERR_ALREADY_HELD,
            "You already hold this badge.",
        );
    }
    // Item 5: the claim is counted before anything is issued.
    let now = Utc::now();
    let rec = match badges::claims::reserve(&state.badges_ks, &code, &entry_id, now).await {
        Ok(Ok(r)) => r,
        Ok(Err(badges::claims::Refusal::CodeInvalid)) => return invalid(),
        Ok(Err(badges::claims::Refusal::AlreadyClaimed)) => {
            return declared(
                &doc,
                REDEEM_ERR_ALREADY_CLAIMED,
                "You have already claimed this code.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 4: credential first, then the award and the membership.
    let (issued, award) = match badges::credential::issue_with_new_award(
        state,
        &group,
        &badge,
        &view.who.did,
        &entry_id,
        rec.created_by.as_deref(),
        "claimed",
    )
    .await
    {
        Ok(x) => x,
        Err(f) => {
            if let Err(e) =
                badges::claims::release(&state.badges_ks, &rec.claim_id, &entry_id).await
            {
                tracing::warn!(error = %e, "could not give back a claim whose issue failed");
            }
            return failure_refusal(
                &doc,
                f,
                REDEEM_ERR_KEY_HOLDER_UNAVAILABLE,
                REDEEM_ERR_KEY_HOLDER_REFUSED,
            );
        }
    };
    badges::credential::offer(state, &group, &view.who.did, &issued).await;
    {
        let ks = state.directory.ks();
        let _dir = crate::directory::WRITE_LOCK.lock().await;
        let existing = match groups::membership(ks, &group.group_id, &entry_id).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let m = Membership {
            group_id: group.group_id.clone(),
            entry_id: entry_id.clone(),
            source: existing
                .as_ref()
                .map_or("claimed".to_string(), |m| m.source.clone()),
            since: existing.as_ref().map_or(now, |m| m.since),
            state: "active".into(),
            credential_id: Some(issued.credential_id.clone()),
            credential_valid_until: Some(issued.valid_until),
        };
        if let Err(e) = groups::put_membership(ks, &m).await {
            return app_error_to_reject(&doc, &e);
        }
    }
    success_response(&doc, json!({ "award": award.wire(true) }))
}

/// `awards/list/0.1`: the owners' view, hidden holders marked (VTI-BDG-030).
async fn handle_awards_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<awards_list::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge_id = str_of(&p, "badgeId").unwrap_or_default();
    let badge = match view.visible(state, badge_id).await {
        Ok(Some(b)) if view.admin || (badge_is_community(&b) && view.owns(&b)) => b,
        Ok(_) => {
            return declared(
                &doc,
                AWARDS_LIST_ERR_NOT_FOUND,
                "No badge you own has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let state_filter = str_of(&p, "state").and_then(AwardState::parse);
    let entry_filter = str_of(&p, "entryId");
    let all: Vec<Award> = match badges::awards_of_badge(&state.badges_ks, &badge.badge_id).await {
        Ok(a) => a
            .into_iter()
            .filter(|a| state_filter.is_none_or(|s| a.state == s))
            .filter(|a| entry_filter.is_none_or(|e| a.entry_id == e))
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!(
        "badges/awards/list|{}|{}|{}|{}",
        view.who.did,
        badge.badge_id,
        state_filter.map_or("", AwardState::as_str),
        entry_filter.unwrap_or("")
    );
    let offset = match offset_of(&p, &binding) {
        Ok(o) => o,
        Err(()) => {
            return declared(
                &doc,
                AWARDS_LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for these filters.",
            );
        }
    };
    let (items, next) = page(&all, offset, limit_of(&p), &binding);
    let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut out = Vec::with_capacity(items.len());
    for a in &items {
        let hidden = match badges::prefs(&state.badges_ks, &a.entry_id).await {
            Ok(pr) => pr.is_hidden(&a.badge_id),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let mut item = json!({ "award": a.wire(true), "hidden": hidden });
        if let Some(f) = projected_fields(state, &viewer, &a.entry_id).await {
            item["fields"] = f;
        }
        out.push(item);
    }
    let mut body = json!({ "items": out });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

fn badge_is_community(b: &Badge) -> bool {
    b.kind == BadgeKind::Community
}

// ─── walls and holders ───────────────────────────────────────────────────

/// `holders/list/0.1` (VTI-BDG-033).
async fn handle_holders_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<holders_list::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let badge = match view
        .visible(state, str_of(&p, "badgeId").unwrap_or_default())
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return declared(
                &doc,
                HOLDERS_ERR_NOT_FOUND,
                "No badge whose holders you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    match view.sees_holders(state, &badge).await {
        Ok(true) => {}
        Ok(false) => {
            return declared(
                &doc,
                HOLDERS_ERR_NOT_FOUND,
                "No badge whose holders you may see has this identifier.",
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let holders = match badges::shown_holders(&state.badges_ks, &badge.badge_id).await {
        Ok(h) => h,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!("badges/holders/list|{}|{}", view.who.did, badge.badge_id);
    let offset = match offset_of(&p, &binding) {
        Ok(o) => o,
        Err(()) => {
            return declared(
                &doc,
                HOLDERS_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for this badge.",
            );
        }
    };
    let total = holders.len();
    let (items, next) = page(&holders, offset, limit_of(&p), &binding);
    let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut out = Vec::with_capacity(items.len());
    for (entry_id, h) in &items {
        let mut item = json!({
            "entryId": entry_id,
            "count": h.count,
            "since": h.since,
            "latestAt": h.latest_at,
        });
        if let Some(f) = projected_fields(state, &viewer, entry_id).await {
            item["fields"] = f;
        }
        out.push(item);
    }
    let mut body = json!({ "items": out, "total": total });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

/// `wall/show/0.1` (VTI-BDG-031).
async fn handle_wall_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<wall_show::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let entry_id = str_of(&p, "entryId").unwrap_or_default().to_string();
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let hidden = || {
        declared(
            &doc,
            WALL_ERR_NOT_FOUND,
            "No entry you may see has this identifier.",
        )
    };
    if !view.settings.enabled && !view.admin {
        return hidden();
    }
    let own = view.entry_id.as_deref() == Some(entry_id.as_str());
    // The directory shows the caller this card, and the member shows their wall.
    if !own {
        let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
            Ok(v) => v,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        use crate::directory::read::{ShowBy, show};
        if show(state, &viewer, &ShowBy::Entry(entry_id.clone()))
            .await
            .is_err()
        {
            return hidden();
        }
    }
    let prefs = match badges::prefs(&state.badges_ks, &entry_id).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !own && prefs.visibility != "members" {
        return hidden();
    }
    let holdings = match badges::holdings_of(&state.badges_ks, &entry_id).await {
        Ok(h) => h,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let held: Vec<&str> = holdings
        .keys()
        .map(String::as_str)
        .filter(|id| !prefs.is_hidden(id))
        .collect();
    let mut entries = Vec::new();
    for id in prefs.arrange(held.iter().copied()) {
        let Some(h) = holdings.get(&id) else { continue };
        let badge = match badges::get_badge(&state.badges_ks, &id).await {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        // A retired badge leaves every wall but its holder's own list (VTI-BDG-005).
        if !badge.is_active() {
            continue;
        }
        let wire = match view.badge_wire(state, &badge).await {
            Ok(w) => w,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        entries.push(json!({
            "badge": wire,
            "count": h.count,
            "since": h.since,
            "latestAt": h.latest_at,
            "pinned": prefs.is_pinned(&id),
        }));
    }
    let mut body = json!({ "entries": entries, "visibility": prefs.visibility });
    if view.settings.show_kudos_totals {
        let all = match badges::all_badges(&state.badges_ks).await {
            Ok(b) => b,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        match badges::kudos_total(&state.badges_ks, &entry_id, &all).await {
            Ok(n) => body["kudosTotal"] = json!(n),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    success_response(&doc, body)
}

// ─── the holder's own ────────────────────────────────────────────────────

/// The signer as a holder: an active member with an entry.
async fn holder(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(View, String), TrustTaskOutcome> {
    let who = member(state, ctx, doc).await?;
    if !who.active_member {
        return Err(denied(doc, "only an active member holds badges"));
    }
    let entry_id = own_entry(state, &who)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let mut view = View::read(state, who)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    view.entry_id = Some(entry_id.clone());
    Ok((view, entry_id))
}

/// `mine/list/0.1`.
async fn handle_mine_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<mine_list::Payload>(&doc) {
        return r;
    }
    let prefs = match badges::prefs(&state.badges_ks, &entry_id).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !view.settings.enabled {
        return success_response(
            &doc,
            json!({ "badges": [], "offers": [], "visibility": prefs.visibility }),
        );
    }
    let mine = match my_badges(state, &view, &prefs).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut offers = Vec::new();
    let awards = match badges::awards_to(&state.badges_ks, &entry_id).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    for a in awards.iter().filter(|a| a.is_open()) {
        let Ok(Some(badge)) = badges::get_badge(&state.badges_ks, &a.badge_id).await else {
            continue;
        };
        if !badge.is_active() {
            continue;
        }
        let wire = match view.badge_wire(state, &badge).await {
            Ok(w) => w,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let mut item = json!({ "award": a.wire(true), "badge": wire });
        if let Some(g) = &a.given_by
            && let Some(f) = projected_fields(state, &viewer, g).await
        {
            item["givenBy"] = f;
        }
        offers.push(item);
    }
    let mut body = json!({ "badges": mine, "offers": offers, "visibility": prefs.visibility });
    if view.settings.show_kudos_totals {
        let all = match badges::all_badges(&state.badges_ks).await {
            Ok(b) => b,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        match badges::kudos_total(&state.badges_ks, &entry_id, &all).await {
            Ok(n) => body["kudosTotal"] = json!(n),
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    success_response(&doc, body)
}

/// `mine/accept/0.1` (items 1 – 7): credential first, membership after (VTI-BDG-021).
async fn handle_accept(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, ACCEPT_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<mine_accept::Payload>(&doc) {
        return r;
    }
    let award_id = str_of(&doc.payload, "awardId")
        .unwrap_or_default()
        .to_string();
    // Items 2 – 3, under the lock; then the remote step without it.
    let (award, badge, group) = {
        let _guard = badges::WRITE_LOCK.lock().await;
        let award = match badges::get_award(&state.badges_ks, &award_id).await {
            Ok(Some(a)) if a.entry_id == entry_id => a,
            Ok(_) => return not_found(&doc, "award"),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if !award.is_open() {
            return declared_with(
                &doc,
                ACCEPT_ERR_ALREADY_DECIDED,
                "This offer is no longer open.",
                json!({ "state": award.state.as_str() }),
            );
        }
        let badge = match badges::get_badge(&state.badges_ks, &award.badge_id).await {
            Ok(Some(b)) => b,
            Ok(None) => return declared(&doc, ACCEPT_ERR_BADGE_RETIRED, "This badge is gone."),
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let group = match &badge.group_id {
            Some(g) => match groups::get(state.directory.ks(), g).await {
                Ok(g) => g,
                Err(e) => return app_error_to_reject(&doc, &e),
            },
            None => None,
        };
        if !badge.is_active() || (badge.is_community() && group.is_none()) {
            let mut a = award;
            a.state = AwardState::Withdrawn;
            a.decided_at = Some(Utc::now());
            let _ = badges::put_award(&state.badges_ks, &a).await;
            return declared(
                &doc,
                ACCEPT_ERR_BADGE_RETIRED,
                "This badge was retired; the offer is closed.",
            );
        }
        (award, badge, group)
    };
    let now = Utc::now();
    let mut accepted = award.clone();
    accepted.state = AwardState::Accepted;
    accepted.decided_at = Some(now);
    // Item 4: the credential, as the group, before anything is recorded.
    let issued = if let Some(group) = &group {
        let mut evidence =
            match badges::accepted_of(&state.badges_ks, &badge.badge_id, &entry_id).await {
                Ok(a) => a,
                Err(e) => return app_error_to_reject(&doc, &e),
            };
        evidence.push(accepted.clone());
        match badges::credential::issue(
            state,
            group,
            &badge,
            &view.who.did,
            Some(&entry_id),
            &evidence,
        )
        .await
        {
            Ok(i) => {
                badges::credential::offer(state, group, &view.who.did, &i).await;
                Some(i)
            }
            Err(f) => {
                return failure_refusal(
                    &doc,
                    f,
                    ACCEPT_ERR_KEY_HOLDER_UNAVAILABLE,
                    ACCEPT_ERR_KEY_HOLDER_REFUSED,
                );
            }
        }
    } else {
        None
    };
    // Item 5: then the record, if the offer is still open.
    let _guard = badges::WRITE_LOCK.lock().await;
    match badges::get_award(&state.badges_ks, &award_id).await {
        Ok(Some(a)) if a.is_open() => {}
        Ok(Some(a)) => {
            return declared_with(
                &doc,
                ACCEPT_ERR_ALREADY_DECIDED,
                "This offer closed while the credential was issued.",
                json!({ "state": a.state.as_str() }),
            );
        }
        Ok(None) => return not_found(&doc, "award"),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    accepted.credential_id = issued.as_ref().map(|i| i.credential_id.clone());
    if let Err(e) = audit(state, &view.who.did, award_changed(&accepted, "accepted")).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_award(&state.badges_ks, &accepted).await {
        return app_error_to_reject(&doc, &e);
    }
    // An automatic badge may count accepted kudos (VTI-BDG-015).
    if badge.kind == BadgeKind::Kudos {
        groups::dynamic::kick();
    }
    if let Some(group) = &group {
        let ks = state.directory.ks();
        let _dir = crate::directory::WRITE_LOCK.lock().await;
        let existing = match groups::membership(ks, &group.group_id, &entry_id).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let m = Membership {
            group_id: group.group_id.clone(),
            entry_id: entry_id.clone(),
            source: existing
                .as_ref()
                .map_or("added".to_string(), |m| m.source.clone()),
            since: existing.as_ref().map_or(now, |m| m.since),
            state: "active".into(),
            credential_id: issued.as_ref().map(|i| i.credential_id.clone()),
            credential_valid_until: issued.as_ref().map(|i| i.valid_until),
        };
        if let Err(e) = groups::put_membership(ks, &m).await {
            return app_error_to_reject(&doc, &e);
        }
    }
    let view = match View::read(state, view.who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let prefs = match badges::prefs(&state.badges_ks, &entry_id).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let held: Vec<&str> = view.holdings.keys().map(String::as_str).collect();
    let position = prefs
        .arrange(held.iter().copied())
        .iter()
        .position(|id| id == &badge.badge_id)
        .unwrap_or(0);
    let Some(h) = view.holdings.get(&badge.badge_id) else {
        return app_error_to_reject(
            &doc,
            &AppError::Internal("the award was not recorded".into()),
        );
    };
    match my_badge(state, &view, &badge, h, &prefs, position).await {
        Ok(b) => success_response(&doc, json!({ "award": accepted.wire(true), "badge": b })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `mine/decline/0.1`.
async fn handle_decline(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, DECLINE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<mine_decline::Payload>(&doc) {
        return r;
    }
    let _guard = badges::WRITE_LOCK.lock().await;
    let mut award = match badges::get_award(
        &state.badges_ks,
        str_of(&doc.payload, "awardId").unwrap_or_default(),
    )
    .await
    {
        Ok(Some(a)) if a.entry_id == entry_id => a,
        Ok(_) => return not_found(&doc, "award"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !award.is_open() {
        return declared_with(
            &doc,
            DECLINE_ERR_ALREADY_DECIDED,
            "This offer is no longer open.",
            json!({ "state": award.state.as_str() }),
        );
    }
    award.state = AwardState::Declined;
    award.decided_at = Some(Utc::now());
    if let Err(e) = audit(state, &view.who.did, award_changed(&award, "declined")).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_award(&state.badges_ks, &award).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "award": award.wire(true) }))
}

/// `mine/hide/0.1` and `mine/show/0.1` (VTI-BDG-030).
async fn handle_hide(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    hide: bool,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let off = if hide {
        HIDE_ERR_BADGES_OFF
    } else {
        SHOW_AGAIN_ERR_BADGES_OFF
    };
    if let Err(r) = settings_on(state, &doc, off).await {
        return r;
    }
    let parsed = if hide {
        parse_spec_payload::<mine_hide::Payload>(&doc).map(drop)
    } else {
        parse_spec_payload::<mine_show::Payload>(&doc).map(drop)
    };
    if let Err(r) = parsed {
        return r;
    }
    let badge_id = str_of(&doc.payload, "badgeId")
        .unwrap_or_default()
        .to_string();
    let Some(h) = view.holdings.get(&badge_id).cloned() else {
        return not_found(&doc, "badge");
    };
    let badge = match badges::get_badge(&state.badges_ks, &badge_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&doc, "badge"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let _guard = badges::WRITE_LOCK.lock().await;
    let mut prefs = match badges::prefs(&state.badges_ks, &entry_id).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if hide {
        prefs.hidden.insert(badge_id.clone());
        prefs.pinned.retain(|b| b != &badge_id);
    } else {
        prefs.hidden.remove(&badge_id);
    }
    let mut data = changed(&badge_id, if hide { "hidden" } else { "shown" });
    data.entry_id = Some(entry_id.clone());
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_prefs(&state.badges_ks, &prefs).await {
        return app_error_to_reject(&doc, &e);
    }
    let held: Vec<&str> = view.holdings.keys().map(String::as_str).collect();
    let position = prefs
        .arrange(held.iter().copied())
        .iter()
        .position(|id| id == &badge_id)
        .unwrap_or(0);
    match my_badge(state, &view, &badge, &h, &prefs, position).await {
        Ok(b) => success_response(&doc, json!({ "badge": b })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `mine/arrange/0.1` (VTI-BDG-032).
async fn handle_arrange(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = settings_on(state, &doc, ARRANGE_ERR_BADGES_OFF).await {
        return r;
    }
    if let Err(r) = parse_spec_payload::<mine_arrange::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let _guard = badges::WRITE_LOCK.lock().await;
    let mut prefs = match badges::prefs(&state.badges_ks, &entry_id).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let not_held = |ids: &[String]| ids.iter().find(|id| !view.holds(id)).cloned();
    if let Some(order) = string_list(&p, "order") {
        if let Some(id) = not_held(&order) {
            return declared_with(
                &doc,
                ARRANGE_ERR_BADGE_NOT_HELD,
                "You do not hold this badge.",
                json!({ "badgeId": id }),
            );
        }
        prefs.order = order;
    }
    if let Some(pinned) = string_list(&p, "pinned") {
        if let Some(id) = not_held(&pinned) {
            return declared_with(
                &doc,
                ARRANGE_ERR_BADGE_NOT_HELD,
                "You do not hold this badge.",
                json!({ "badgeId": id }),
            );
        }
        if let Some(id) = pinned.iter().find(|id| prefs.is_hidden(id)) {
            return declared_with(
                &doc,
                ARRANGE_ERR_BADGE_HIDDEN,
                "A hidden badge cannot be pinned.",
                json!({ "badgeId": id }),
            );
        }
        let max = view.settings.limits.max_pinned();
        if pinned.len() > max {
            return declared_with(
                &doc,
                ARRANGE_ERR_TOO_MANY_PINNED,
                "Too many badges pinned.",
                json!({ "limit": max }),
            );
        }
        prefs.pinned = pinned;
    }
    if let Some(v) = str_of(&p, "visibility") {
        prefs.visibility = v.to_string();
    }
    let mut data = changed("-", "arranged");
    data.entry_id = Some(entry_id.clone());
    if let Err(e) = audit(state, &view.who.did, data).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_prefs(&state.badges_ks, &prefs).await {
        return app_error_to_reject(&doc, &e);
    }
    match my_badges(state, &view, &prefs).await {
        Ok(b) => success_response(&doc, json!({ "badges": b, "visibility": prefs.visibility })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── kudos ───────────────────────────────────────────────────────────────

/// `kudos/give/0.1` (VTI-BDG-040, VTI-BDG-041).
async fn handle_kudos_give(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (view, entry_id) = match holder(state, ctx, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let settings = match settings_on(state, &doc, KUDOS_ERR_BADGES_OFF).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<kudos_give::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let badge = match view
        .visible(state, str_of(&p, "badgeId").unwrap_or_default())
        .await
    {
        Ok(Some(b)) if b.is_active() => b,
        Ok(_) => return not_found(&doc, "badge"),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if badge.kind == BadgeKind::Community {
        return declared(
            &doc,
            KUDOS_ERR_KIND_MISMATCH,
            format!(
                "{} is a community badge: its owners give it with vtc/badges/awards/offer.",
                badge.name
            ),
        );
    }
    let to = str_of(&p, "to").unwrap_or_default().to_string();
    if to == entry_id {
        return declared(
            &doc,
            KUDOS_ERR_SELF_GIVING,
            "Nobody gives themselves kudos.",
        );
    }
    let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let recipient_active = match active_entry(state, &to).await {
        Ok(d) => d.is_some(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !recipient_active || !directory_shows(state, &viewer, &to).await {
        return not_found(&doc, "member");
    }
    // Tenure.
    match crate::member_portal::active::active_member(state, &view.who.did).await {
        Ok(Some(m)) => {
            let from =
                m.member.joined_at + Duration::days(i64::from(settings.limits.min_tenure_days()));
            if from > Utc::now() {
                return declared_with(
                    &doc,
                    KUDOS_ERR_NOT_ELIGIBLE,
                    "You have not been a member long enough to give kudos.",
                    json!({ "eligibleFrom": from }),
                );
            }
        }
        Ok(None) => return denied(&doc, "only an active member gives kudos"),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    let now = Utc::now();
    let _guard = badges::WRITE_LOCK.lock().await;
    // Limits: every giving counts, whatever its later state.
    let given = match badges::awards_given_by(&state.badges_ks, &entry_id).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let kudos_ids: BTreeSet<String> = match badges::all_badges(&state.badges_ks).await {
        Ok(b) => b
            .into_iter()
            .filter(|b| b.kind == BadgeKind::Kudos)
            .map(|b| b.badge_id)
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let today = given
        .iter()
        .filter(|a| kudos_ids.contains(&a.badge_id) && a.offered_at > now - Duration::days(1))
        .count();
    if today >= settings.limits.kudos_per_giver_per_day() as usize {
        let until = given
            .iter()
            .map(|a| a.offered_at)
            .min()
            .map(|t| t + Duration::days(1));
        return declared_with(
            &doc,
            KUDOS_ERR_LIMIT_REACHED,
            "You have given as many kudos today as this community allows.",
            json!({ "limit": "kudosPerGiverPerDay", "until": until }),
        );
    }
    let window = match settings.limits.same_giver_same_member() {
        "day" => Some(Duration::days(1)),
        "week" => Some(Duration::days(7)),
        _ => None,
    };
    if let Some(w) = window
        && let Some(last) = given
            .iter()
            .filter(|a| {
                a.entry_id == to && kudos_ids.contains(&a.badge_id) && a.offered_at > now - w
            })
            .map(|a| a.offered_at)
            .max()
    {
        return declared_with(
            &doc,
            KUDOS_ERR_LIMIT_REACHED,
            "You gave this member kudos recently.",
            json!({ "limit": "sameGiverSameMember", "until": last + w }),
        );
    }
    let a = Award {
        award_id: badges::new_award_id(),
        badge_id: badge.badge_id.clone(),
        entry_id: to,
        given_by: Some(entry_id),
        note: str_of(&p, "note").map(str::to_string),
        state: AwardState::Offered,
        offered_at: now,
        decided_at: None,
        expires_at: settings
            .limits
            .offer_expires_after_days
            .map(|d| now + Duration::days(i64::from(d))),
        credential_id: None,
        revoke_reason: None,
        shared: None,
    };
    if let Err(e) = audit(state, &view.who.did, award_changed(&a, "kudosGiven")).await {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(e) = badges::put_award(&state.badges_ks, &a).await {
        return app_error_to_reject(&doc, &e);
    }
    success_response(&doc, json!({ "award": a.wire(true) }))
}

/// `kudos/list/0.1` (VTI-BDG-042).
async fn handle_kudos_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // An administrator reads every giving of a badge (`all`) without being a holder.
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<kudos_list::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let all = bool_of(&p, "all").unwrap_or(false);
    let delegated = ctx.verified_signer.as_deref().is_some_and(|s| s != who.did);
    let view = match View::read(state, who).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if all && (!view.admin || delegated) {
        return denied(
            &doc,
            "listing every giving of a badge takes vtc.badges.admin, with your own key",
        );
    }
    let entry_id = match (&view.entry_id, all) {
        (Some(e), _) => e.clone(),
        (None, true) => String::new(),
        (None, false) => return denied(&doc, "only an active member holds badges"),
    };
    let direction = str_of(&p, "direction").unwrap_or("received");
    let badge_filter = str_of(&p, "badgeId").map(str::to_string);
    let state_filter = str_of(&p, "state").and_then(AwardState::parse);
    let kudos_ids: BTreeSet<String> = match badges::all_badges(&state.badges_ks).await {
        Ok(b) => b
            .into_iter()
            .filter(|b| b.kind == BadgeKind::Kudos)
            .map(|b| b.badge_id)
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let source = if all {
        match &badge_filter {
            Some(b) => badges::awards_of_badge(&state.badges_ks, b).await,
            None => Ok(Vec::new()),
        }
    } else if direction == "given" {
        badges::awards_given_by(&state.badges_ks, &entry_id).await
    } else {
        badges::awards_to(&state.badges_ks, &entry_id).await
    };
    let items: Vec<Award> = match source {
        Ok(a) => a
            .into_iter()
            .filter(|a| kudos_ids.contains(&a.badge_id))
            .filter(|a| badge_filter.as_ref().is_none_or(|b| &a.badge_id == b))
            .filter(|a| state_filter.is_none_or(|s| a.state == s))
            .collect(),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let binding = format!(
        "badges/kudos/list|{}|{direction}|{all}|{}|{}",
        view.who.did,
        badge_filter.as_deref().unwrap_or(""),
        state_filter.map_or("", AwardState::as_str)
    );
    let offset = match offset_of(&p, &binding) {
        Ok(o) => o,
        Err(()) => {
            return declared(
                &doc,
                KUDOS_LIST_ERR_CURSOR_INVALID,
                "This cursor is not this caller's for these filters.",
            );
        }
    };
    let (items, next) = page(&items, offset, limit_of(&p), &binding);
    let viewer = match crate::directory::read::viewer(state, &view.who.did).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut out = Vec::with_capacity(items.len());
    for a in &items {
        let Ok(Some(badge)) = badges::get_badge(&state.badges_ks, &a.badge_id).await else {
            continue;
        };
        let wire = match view.badge_wire(state, &badge).await {
            Ok(w) => w,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let mut item = json!({ "award": a.wire(true), "badge": wire });
        if all {
            if let Some(g) = &a.given_by
                && let Some(f) = projected_fields(state, &viewer, g).await
            {
                item["giver"] = f;
            }
            if let Some(f) = projected_fields(state, &viewer, &a.entry_id).await {
                item["recipient"] = f;
            }
        } else {
            let other = if direction == "given" {
                Some(a.entry_id.clone())
            } else {
                a.given_by.clone()
            };
            if let Some(o) = other
                && let Some(f) = projected_fields(state, &viewer, &o).await
            {
                item["counterpart"] = f;
            }
        }
        out.push(item);
    }
    let mut body = json!({ "items": out });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}
