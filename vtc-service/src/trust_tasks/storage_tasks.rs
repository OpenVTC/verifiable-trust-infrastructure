//! Where this community keeps its rooms' files — `vtc/storage/configs/{list,get,create,
//! update,retire,probe}/0.1` and `vtc/rooms/storage/assign/0.1`
//! (`docs/05-design-notes/data-rooms-files.md` §7; [`crate::rooms::storage_configs`]).
//!
//! The authority is `vtc.rooms.admin`, read from the signer's own entry at execution
//! time: the host's authority over rooms, never a room's. No room-issued credential is
//! required or accepted, and nothing here needs or could use a room key.
//!
//! - **Reads** (`list`, `get`) and the **probe** answer a holder of `vtc.rooms.admin`.
//! - **Changes** (`create`, `update`, `retire`, `assign`) decide where members' files go
//!   and what reaches them, so each is parked for the other holders' consent after the
//!   requester's operation-bound step-up ([`super::acl_tasks::settle_consent_gate`],
//!   [`Act::ChangeStorage`]) and executes itself on the N-th approval, every check
//!   re-run against the community as it is then. A request that would change nothing —
//!   retiring a config already retiring, assigning a room to the config it is on — is
//!   answered at once and parks nothing.
//!
//! No member of any of these tasks carries a credential, and no answer returns one.

use std::collections::HashMap;

use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::rooms::storage::assign::v0_1 as assign;
use trust_tasks_rs::specs::vtc::storage::configs::{
    create::v0_1 as create, get::v0_1 as get, list::v0_1 as list, probe::v0_1 as probe,
    retire::v0_1 as retire, update::v0_1 as update,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, RoomStorageChangedData};
use vti_common::auth::extractor::AuthClaims;
use vti_common::blob_store::{BlobKey, PROBE_PREFIX};
use vti_rooms::blobs::ConfigHoldings;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::acl::admin_consent::Act;
use crate::rooms::storage_configs::{SettingsError, kind_of, state_of};
use crate::routes::acl::conform;
use crate::server::AppState;

pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const GET_TYPE: &str = <get::Payload as Payload>::TYPE_URI;
pub(crate) const CREATE_TYPE: &str = <create::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <update::Payload as Payload>::TYPE_URI;
pub(crate) const RETIRE_TYPE: &str = <retire::Payload as Payload>::TYPE_URI;
pub(crate) const PROBE_TYPE: &str = <probe::Payload as Payload>::TYPE_URI;
pub(crate) const ASSIGN_TYPE: &str = <assign::Payload as Payload>::TYPE_URI;

/// Every URI this module routes.
pub(crate) const URIS: &[&str] = &[
    LIST_TYPE,
    GET_TYPE,
    CREATE_TYPE,
    UPDATE_TYPE,
    RETIRE_TYPE,
    PROBE_TYPE,
    ASSIGN_TYPE,
];

/// At most this many room identifiers in a `get` (`vtc/storage/configs/get` item 2).
const ASSIGNED_ROOMS_SHOWN: usize = 100;
/// A `list` page when the caller names no `limit`.
const DEFAULT_PAGE: usize = 50;
/// A list cursor names the last identifier returned, after this prefix.
const CURSOR_PREFIX: &str = "storage-configs:";
/// A probe's backend error, truncated to this (`vtc/storage/configs/probe` item 4).
const PROBE_ERROR_MAX: usize = 2048;

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        LIST_TYPE => handle_list(state, ctx, doc).await,
        GET_TYPE => handle_get(state, ctx, doc).await,
        CREATE_TYPE => handle_create(state, ctx, doc).await,
        UPDATE_TYPE => handle_update(state, ctx, doc).await,
        RETIRE_TYPE => handle_retire(state, ctx, doc).await,
        PROBE_TYPE => handle_probe(state, ctx, doc).await,
        ASSIGN_TYPE => handle_assign(state, ctx, doc).await,
        _ => return None,
    })
}

pub(super) fn refuse(
    doc: &TrustTask<Value>,
    code: &str,
    message: impl Into<String>,
    details: Option<Value>,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, details)
}

pub(super) fn malformed(doc: &TrustTask<Value>, reason: impl Into<String>) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::MalformedRequest {
            reason: reason.into(),
        },
    )
}

pub(super) fn respond<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    body: Value,
) -> TrustTaskOutcome {
    match conform::<R>(body) {
        Ok(r) => super::helpers::success_response(doc, r),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// The signer, held to `vtc.rooms.admin` on its own live entry.
pub(super) async fn rooms_admin(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<AuthClaims, TrustTaskOutcome> {
    let actor = admin_signer(state, ctx, doc).await?;
    crate::acl::require_capability(&state.acl_ks, &actor.did, Capability::RoomsAdmin, None)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    Ok(actor)
}

/// A refusal of proposed settings, under the codes `task` declares.
fn settings_refusal(
    doc: &TrustTask<Value>,
    invalid: &str,
    auth_not_allowed: &str,
    unknown_account: &str,
    e: SettingsError,
) -> TrustTaskOutcome {
    match e {
        SettingsError::Invalid { member, reason } => refuse(
            doc,
            invalid,
            format!("{member} {reason}"),
            Some(json!({ "member": member, "problem": truncate(&reason, 500) })),
        ),
        SettingsError::AuthNotAllowed(reason) => refuse(doc, auth_not_allowed, reason, None),
        SettingsError::UnknownAccount(reason) => refuse(doc, unknown_account, reason, None),
    }
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

async fn holdings(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<HashMap<String, ConfigHoldings>, TrustTaskOutcome> {
    state
        .room_files
        .config_holdings()
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// Record a storage change in the audit trail. A failure is logged, not returned: the
/// change has already been written.
async fn audit(state: &AppState, actor: &str, data: RoomStorageChangedData) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let event = data.event.clone();
    if let Err(e) = writer
        .write(actor, None, AuditEvent::RoomStorageChanged(data))
        .await
    {
        tracing::warn!(error = %e, %event, "could not audit a storage change");
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ─── reads ───────────────────────────────────────────────────────────────

/// `vtc/storage/configs/list/0.1` — every config, `retired` ones included, with its
/// facts computed now.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let checked: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let after = match checked.cursor.as_deref() {
        None => None,
        Some(c) => match c.strip_prefix(CURSOR_PREFIX) {
            Some(id) if !id.is_empty() => Some(id.to_string()),
            _ => {
                return refuse(
                    &doc,
                    list::error_codes::INVALID_CURSOR.code,
                    "that cursor was not issued by this community",
                    None,
                );
            }
        },
    };
    let limit = checked
        .limit
        .map(|l| l.get() as usize)
        .unwrap_or(DEFAULT_PAGE);
    let want_state = checked.state.map(|s| s.to_string());
    let want_kind = checked.kind.map(|k| k.to_string());

    let configs = match state.room_storage.configs().await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let held = match holdings(state, &doc).await {
        Ok(h) => h,
        Err(reject) => return reject,
    };
    let matching: Vec<Value> = configs
        .into_iter()
        .filter(|c| {
            after
                .as_deref()
                .is_none_or(|a| c["id"].as_str().is_some_and(|id| id > a))
        })
        .filter(|c| want_state.as_deref().is_none_or(|s| state_of(c) == s))
        .filter(|c| {
            want_kind
                .as_deref()
                .is_none_or(|k| kind_of(&c["settings"]) == k)
        })
        .collect();
    let more = matching.len() > limit;
    let mut items = Vec::new();
    for config in matching.into_iter().take(limit) {
        let id = config["id"].as_str().unwrap_or_default().to_string();
        let facts = match state
            .room_storage
            .facts(&config, &held.get(&id).copied().unwrap_or_default())
            .await
        {
            Ok(f) => f,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        items.push(json!({ "config": config, "facts": facts }));
    }
    let mut body = json!({ "items": items });
    if more && let Some(last) = body["items"].as_array().and_then(|i| i.last()) {
        body["nextCursor"] = json!(format!(
            "{CURSOR_PREFIX}{}",
            last["config"]["id"].as_str().unwrap_or_default()
        ));
    }
    respond::<list::Response>(&doc, body)
}

/// `vtc/storage/configs/get/0.1` — one config, its facts and the rooms on it.
async fn handle_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let checked: get::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = checked.config_id.as_str();
    let config = match state.room_storage.config(id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return refuse(
                &doc,
                get::error_codes::NOT_FOUND.code,
                format!("no storage config `{id}`"),
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let held = match holdings(state, &doc).await {
        Ok(h) => h,
        Err(reject) => return reject,
    };
    let facts = match state
        .room_storage
        .facts(&config, &held.get(id).copied().unwrap_or_default())
        .await
    {
        Ok(f) => f,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let rooms = match state.room_storage.rooms_on(id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    respond::<get::Response>(
        &doc,
        json!({
            "config": config,
            "facts": facts,
            "assignedRoomsTruncated": rooms.len() > ASSIGNED_ROOMS_SHOWN,
            "assignedRooms": rooms.into_iter().take(ASSIGNED_ROOMS_SHOWN).collect::<Vec<_>>(),
        }),
    )
}

// ─── create ──────────────────────────────────────────────────────────────

/// `vtc/storage/configs/create/0.1`.
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: create::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = checked.id.as_str().to_string();
    let settings = doc.payload["settings"].clone();
    let auth = doc.payload.get("auth").cloned();

    if let Some(reject) = create_refusal(state, &doc, &id, &settings, auth.as_ref(), false).await {
        return reject;
    }

    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeStorage,
        &id,
        &format!("Add the storage config {id}"),
        &format!("Add the storage config {id}"),
    )
    .await
    {
        return reject;
    }

    let _guard = state.room_storage.lock().await;
    // Every check again, against the community as it is now, and the root prepared.
    if let Some(reject) = create_refusal(state, &doc, &id, &settings, auth.as_ref(), true).await {
        return reject;
    }
    let mut record = json!({
        "id": id,
        "label": checked.label.as_str(),
        "settings": settings,
        "state": "active",
        "createdBy": actor.did,
        "createdAt": now_rfc3339(),
    });
    if let Some(a) = auth {
        record["auth"] = a;
    }
    if let Some(cap) = checked.capacity_bytes {
        record["capacityBytes"] = json!(cap);
    }
    if checked.is_default == Some(true) {
        record["isDefault"] = json!(true);
    }
    if let Err(e) = state.room_storage.put_config(record.clone()).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(_guard);

    audit(
        state,
        &actor.did,
        RoomStorageChangedData {
            event: "configCreated".into(),
            config_id: id.clone(),
            room_id: None,
            previous: None,
            current: record.clone(),
            approvers: crate::admin_actions::executing_approvers(state).await,
            reason: checked.reason.as_str().to_string(),
        },
    )
    .await;
    // Item 8: probe it once it exists, and record the result as its health.
    let _ = run_probe(state, &id).await;
    respond::<create::Response>(&doc, json!({ "config": record }))
}

/// Why a create cannot run now, if it cannot. With `prepare`, a `local` root that passes
/// is also created, owner-only.
async fn create_refusal(
    state: &AppState,
    doc: &TrustTask<Value>,
    id: &str,
    settings: &Value,
    auth: Option<&Value>,
    prepare: bool,
) -> Option<TrustTaskOutcome> {
    use create::error_codes as c;
    match state.room_storage.config(id).await {
        Ok(Some(_)) => {
            return Some(refuse(
                doc,
                c::EXISTS.code,
                format!("the storage config identifier `{id}` is, or was, in use"),
                None,
            ));
        }
        Ok(None) => {}
        Err(e) => return Some(app_error_to_reject(doc, &e)),
    }
    if let Err(e) = state
        .room_storage
        .validate(settings, auth, None, prepare)
        .await
    {
        return Some(settings_refusal(
            doc,
            c::INVALID_SETTINGS.code,
            c::AUTH_NOT_ALLOWED.code,
            c::UNKNOWN_ACCOUNT.code,
            e,
        ));
    }
    None
}

// ─── update ──────────────────────────────────────────────────────────────

/// What an update would store, or why it cannot.
async fn plan_update(
    state: &AppState,
    doc: &TrustTask<Value>,
    checked: &update::Payload,
    prepare: bool,
) -> Result<(Value, Value), TrustTaskOutcome> {
    use update::error_codes as c;
    let id = checked.config_id.as_str();
    let current = match state.room_storage.config(id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(refuse(
                doc,
                c::NOT_FOUND.code,
                format!("no storage config `{id}`"),
                None,
            ));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    let p = &doc.payload;
    let new_settings = p.get("settings");
    let new_auth = p.get("auth");

    if let Some(s) = new_settings
        && kind_of(s) != kind_of(&current["settings"])
    {
        return Err(refuse(
            doc,
            c::KIND_IMMUTABLE.code,
            format!(
                "`{id}` stores to `{}`; a config's kind never changes — create another config",
                kind_of(&current["settings"])
            ),
            None,
        ));
    }
    let beyond_label = ["settings", "auth", "capacityBytes", "isDefault"]
        .iter()
        .any(|m| p.get(*m).is_some());
    if state_of(&current) != "active" && beyond_label {
        return Err(refuse(
            doc,
            c::NOT_ACTIVE.code,
            format!(
                "`{id}` is {}; only its label can change",
                state_of(&current)
            ),
            None,
        ));
    }
    if p.get("isDefault").and_then(Value::as_bool) == Some(false)
        && current["isDefault"].as_bool() == Some(true)
    {
        return Err(malformed(
            doc,
            "the default changes by making another config the default, not by clearing it",
        ));
    }
    if let Some(s) = new_settings {
        // The locating settings: where a blob already written would be looked for.
        let moved: Vec<&str> = ["root", "endpoint", "region", "bucket", "prefix"]
            .into_iter()
            .filter(|m| s.get(*m) != current["settings"].get(*m))
            .collect();
        if !moved.is_empty() {
            let held = holdings(state, doc).await?;
            if held.get(id).is_some_and(|h| h.files > 0) {
                return Err(refuse(
                    doc,
                    c::LOCATION_IMMUTABLE.code,
                    format!(
                        "blobs on `{id}` are found by {}; it cannot move while it holds any — \
                         create a config at the new location and migrate the rooms",
                        moved.join(", ")
                    ),
                    Some(json!({
                        "members": moved.iter().map(|m| format!("settings.{m}")).collect::<Vec<_>>(),
                    })),
                ));
            }
        }
    }
    if new_settings.is_some() || new_auth.is_some() {
        let settings = new_settings.unwrap_or(&current["settings"]);
        let auth = new_auth.or(current.get("auth"));
        if let Err(e) = state
            .room_storage
            .validate(settings, auth, Some(id), prepare)
            .await
        {
            return Err(settings_refusal(
                doc,
                c::INVALID_SETTINGS.code,
                c::AUTH_NOT_ALLOWED.code,
                c::UNKNOWN_ACCOUNT.code,
                e,
            ));
        }
    }

    let mut next = current.clone();
    if let Some(label) = p.get("label") {
        next["label"] = label.clone();
    }
    if let Some(s) = new_settings {
        next["settings"] = s.clone();
    }
    if let Some(a) = new_auth {
        next["auth"] = a.clone();
    }
    if let Some(cap) = p.get("capacityBytes") {
        next["capacityBytes"] = cap.clone();
    }
    if p.get("isDefault").and_then(Value::as_bool) == Some(true) {
        next["isDefault"] = json!(true);
    }
    Ok((current, next))
}

/// `vtc/storage/configs/update/0.1`.
async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: update::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = checked.config_id.as_str().to_string();
    if let Err(reject) = plan_update(state, &doc, &checked, false).await {
        return reject;
    }
    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeStorage,
        &id,
        &format!("Change the storage config {id}"),
        &format!("Change the storage config {id}"),
    )
    .await
    {
        return reject;
    }

    let guard = state.room_storage.lock().await;
    let (previous, mut next) = match plan_update(state, &doc, &checked, true).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    next["updatedBy"] = json!(actor.did);
    next["updatedAt"] = json!(now_rfc3339());
    if let Err(e) = state.room_storage.put_config(next.clone()).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(guard);

    audit(
        state,
        &actor.did,
        RoomStorageChangedData {
            event: "configUpdated".into(),
            config_id: id,
            room_id: None,
            previous: Some(previous),
            current: next.clone(),
            approvers: crate::admin_actions::executing_approvers(state).await,
            reason: checked.reason.as_str().to_string(),
        },
    )
    .await;
    respond::<update::Response>(&doc, json!({ "config": next }))
}

// ─── retire ──────────────────────────────────────────────────────────────

/// What retiring would do now: `Ok(None)` when the config is already out of service.
async fn plan_retire(
    state: &AppState,
    doc: &TrustTask<Value>,
    id: &str,
) -> Result<(Value, Option<&'static str>, u64), TrustTaskOutcome> {
    use retire::error_codes as c;
    let current = match state.room_storage.config(id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(refuse(
                doc,
                c::NOT_FOUND.code,
                format!("no storage config `{id}`"),
                None,
            ));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    let remaining = holdings(state, doc)
        .await?
        .get(id)
        .map(|h| h.files)
        .unwrap_or(0);
    if state_of(&current) != "active" {
        return Ok((current, None, remaining));
    }
    let rooms = match state.room_storage.rooms_on(id).await {
        Ok(r) => r.len(),
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    if rooms > 0 {
        return Err(refuse(
            doc,
            c::ROOMS_ASSIGNED.code,
            format!("{rooms} room(s) are assigned to `{id}`; assign them elsewhere first"),
            Some(json!({ "rooms": rooms })),
        ));
    }
    if current["isDefault"].as_bool() == Some(true) {
        return Err(refuse(
            doc,
            c::IS_DEFAULT.code,
            format!("`{id}` is the default; make another config the default first"),
            None,
        ));
    }
    let next = if remaining > 0 { "draining" } else { "retired" };
    Ok((current, Some(next), remaining))
}

/// `vtc/storage/configs/retire/0.1`.
async fn handle_retire(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: retire::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = checked.config_id.as_str().to_string();
    let answer = |state_now: &str, remaining: u64| json!({ "configId": id, "state": state_now, "blobsRemaining": remaining });
    match plan_retire(state, &doc, &id).await {
        // Item 5: already draining or retired — a success that changes nothing.
        Ok((current, None, remaining)) => {
            return respond::<retire::Response>(&doc, answer(state_of(&current), remaining));
        }
        Ok(_) => {}
        Err(reject) => return reject,
    }
    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeStorage,
        &id,
        &format!("Retire the storage config {id}"),
        &format!("Retire the storage config {id}"),
    )
    .await
    {
        return reject;
    }

    let guard = state.room_storage.lock().await;
    let (previous, next_state, remaining) = match plan_retire(state, &doc, &id).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let Some(next_state) = next_state else {
        return respond::<retire::Response>(&doc, answer(state_of(&previous), remaining));
    };
    let mut next = previous.clone();
    next["state"] = json!(next_state);
    next["updatedBy"] = json!(actor.did);
    next["updatedAt"] = json!(now_rfc3339());
    if let Err(e) = state.room_storage.put_config(next.clone()).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(guard);

    audit(
        state,
        &actor.did,
        RoomStorageChangedData {
            event: "configRetired".into(),
            config_id: id.clone(),
            room_id: None,
            previous: Some(previous),
            current: next,
            approvers: crate::admin_actions::executing_approvers(state).await,
            reason: checked.reason.as_str().to_string(),
        },
    )
    .await;
    respond::<retire::Response>(&doc, answer(next_state, remaining))
}

// ─── probe ───────────────────────────────────────────────────────────────

/// Remove what could be a credential from a backend's error: a URL's query (where a
/// presigned signature or token travels) and any long unbroken token.
fn scrub(error: &str) -> String {
    let mut out = String::with_capacity(error.len());
    for word in error.split_inclusive(char::is_whitespace) {
        let (body, tail) = match word.find(char::is_whitespace) {
            Some(i) => word.split_at(i),
            None => (word, ""),
        };
        let body = match body.find('?') {
            Some(i) if body.contains("://") => format!("{}?…", &body[..i]),
            _ => body.to_string(),
        };
        let tokenish = body.len() >= 32
            && body
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c));
        out.push_str(if tokenish { "…" } else { &body });
        out.push_str(tail);
    }
    truncate(&out, PROBE_ERROR_MAX)
}

/// Put, read back and delete a canary under `probe/` with the config's own store,
/// stopping at the first failure; record the outcome as the config's last probe.
async fn run_probe(state: &AppState, id: &str) -> Result<Value, vti_common::error::AppError> {
    let probed_at = chrono::Utc::now();
    let mut steps = Vec::new();
    let mut ok = true;
    let step = |name: &str, started: std::time::Instant, result: Result<(), String>| {
        let mut s = json!({
            "step": name,
            "ok": result.is_ok(),
            "durationMs": started.elapsed().as_millis() as u64,
        });
        if let Err(e) = result {
            s["error"] = json!(scrub(&e));
        }
        s
    };

    let started = std::time::Instant::now();
    let store = state.room_storage.store(id);
    // A store's own account of whether it can reach its backend: for a VTA
    // account, that the VTA issues it a request.
    let authenticated = match &store {
        Some(store) => {
            let health = store.health().await;
            if health.ok {
                Ok(())
            } else {
                Err(health
                    .detail
                    .unwrap_or_else(|| "the store reports itself unhealthy".into()))
            }
        }
        None => Err("this host has no usable store for the config".to_string()),
    };
    ok &= authenticated.is_ok();
    steps.push(step("authenticate", started, authenticated));

    if let Some(store) = store.filter(|_| ok) {
        let key = BlobKey::probe();
        let canary: Vec<u8> = {
            let mut b = vec![0u8; 64];
            rand::fill(&mut b[..]);
            b
        };
        // Staged beside upload staging, under the data directory: `tempfile` is a
        // test-only dependency of this crate, and the system temp directory is
        // not owner-only.
        let staging_dir = state
            .config
            .read()
            .await
            .store
            .data_dir
            .join("room-blob-staging");
        tokio::fs::create_dir_all(&staging_dir).await?;
        let staged = staging_dir.join(format!("probe-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&staged, &canary).await?;

        let started = std::time::Instant::now();
        let put = store
            .put(&key, &staged, canary.len() as u64)
            .await
            .map_err(|e| e.to_string());
        ok &= put.is_ok();
        let at = put.as_ref().ok().cloned();
        steps.push(step("put", started, put.map(|_| ())));

        if let Some(at) = at.filter(|_| ok) {
            let started = std::time::Instant::now();
            let got = match store.get_range(&at, 0, canary.len() as u64).await {
                Ok(bytes) if bytes == canary => Ok(()),
                Ok(_) => Err("the bytes read back differ from those written".to_string()),
                Err(e) => Err(e.to_string()),
            };
            ok &= got.is_ok();
            steps.push(step("get", started, got));

            // Delete even after a failed read: a canary is never left behind on purpose.
            let started = std::time::Instant::now();
            let deleted = store
                .delete(&at)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            ok &= deleted.is_ok();
            steps.push(step("delete", started, deleted));
        }
        let _ = tokio::fs::remove_file(&staged).await;
    }

    state.room_storage.record_probe(id, ok, probed_at).await?;
    // `probe/` beneath the config's own prefix, where the store wrote it.
    let config_prefix = state
        .room_storage
        .config(id)
        .await?
        .and_then(|c| c["settings"]["prefix"].as_str().map(str::to_string))
        .unwrap_or_default();
    Ok(json!({
        "configId": id,
        "ok": ok,
        "probedAt": probed_at.to_rfc3339(),
        "prefix": format!("{config_prefix}{PROBE_PREFIX}"),
        "steps": steps,
    }))
}

/// `vtc/storage/configs/probe/0.1`.
async fn handle_probe(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use probe::error_codes as c;
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let checked: probe::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = checked.config_id.as_str();
    let config = match state.room_storage.config(id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return refuse(
                &doc,
                c::NOT_FOUND.code,
                format!("no storage config `{id}`"),
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if !state.room_storage.usable(&config) {
        return refuse(
            &doc,
            c::CREDENTIAL_REQUIRED.code,
            format!("`{id}` has no usable credential"),
            None,
        );
    }
    match run_probe(state, id).await {
        Ok(body) => respond::<probe::Response>(&doc, body),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── assign ──────────────────────────────────────────────────────────────

/// Why a room cannot be assigned to `config_id` now, if it cannot; else its current
/// config.
async fn plan_assign(
    state: &AppState,
    doc: &TrustTask<Value>,
    room_id: &str,
    config_id: &str,
) -> Result<String, TrustTaskOutcome> {
    use assign::error_codes as c;
    match vti_rooms::storage::get_room(&state.rooms_ks, room_id).await {
        Ok(_) => {}
        Err(vti_common::error::AppError::NotFound(_)) => {
            return Err(refuse(
                doc,
                c::ROOM_NOT_FOUND.code,
                "this community hosts no such room",
                None,
            ));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    }
    let config = match state.room_storage.config(config_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(refuse(
                doc,
                c::CONFIG_NOT_FOUND.code,
                format!("no storage config `{config_id}`"),
                None,
            ));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    if state_of(&config) != "active" {
        return Err(refuse(
            doc,
            c::CONFIG_NOT_ACTIVE.code,
            format!("`{config_id}` is {} and takes no rooms", state_of(&config)),
            None,
        ));
    }
    if !state.room_storage.usable(&config) {
        return Err(refuse(
            doc,
            c::CREDENTIAL_REQUIRED.code,
            format!("`{config_id}` has no usable credential"),
            None,
        ));
    }
    let current = match state.room_storage.assignment(room_id).await {
        Ok(Some(a)) => a.config_id,
        Ok(None) => match state.room_storage.default_id().await {
            Ok(d) => d.unwrap_or_default(),
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        },
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    Ok(current)
}

/// `vtc/rooms/storage/assign/0.1`.
async fn handle_assign(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: assign::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let room_id = checked.room_id.as_str().to_string();
    let config_id = checked.config_id.as_str().to_string();
    let answer = |previous: &str, elsewhere: u64| {
        json!({
            "roomId": room_id,
            "configId": config_id,
            "previousConfigId": previous,
            "blobsOnEarlierConfigs": elsewhere,
        })
    };
    let elsewhere = |state: &AppState| {
        let (room_id, config_id) = (room_id.clone(), config_id.clone());
        let files = state.room_files.clone();
        async move {
            files
                .room_blobs_elsewhere(&room_id, &config_id)
                .await
                .unwrap_or(0)
        }
    };

    let current = match plan_assign(state, &doc, &room_id, &config_id).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    // Item 3: already there — a success that changes nothing.
    if current == config_id {
        return respond::<assign::Response>(&doc, answer(&current, elsewhere(state).await));
    }
    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeStorage,
        &room_id,
        &format!("Store room {room_id}'s new files on {config_id}"),
        &format!("Store room {room_id}'s new files on {config_id}"),
    )
    .await
    {
        return reject;
    }

    let guard = state.room_storage.lock().await;
    let previous = match plan_assign(state, &doc, &room_id, &config_id).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    if previous != config_id
        && let Err(e) = state
            .room_storage
            .write_assignment(&room_id, &config_id, &actor.did)
            .await
    {
        return app_error_to_reject(&doc, &e);
    }
    drop(guard);

    if previous != config_id {
        audit(
            state,
            &actor.did,
            RoomStorageChangedData {
                event: "roomAssigned".into(),
                config_id: config_id.clone(),
                room_id: Some(room_id.clone()),
                previous: Some(json!(previous)),
                current: json!(config_id),
                approvers: crate::admin_actions::executing_approvers(state).await,
                reason: checked.reason.as_str().to_string(),
            },
        )
        .await;
    }
    respond::<assign::Response>(&doc, answer(&previous, elsewhere(state).await))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_error_loses_what_could_be_a_credential() {
        let raw = "PUT https://bucket.s3.amazonaws.com/probe/x?X-Amz-Signature=abc&X-Amz-Credential=AKIA \
                   failed: token eyJhbGciOiJFZERTQSJ9eyJzdWIiOiJ4In0abcdefgh denied";
        let s = scrub(raw);
        assert!(!s.contains("X-Amz-Signature"), "{s}");
        assert!(!s.contains("AKIA"), "{s}");
        assert!(!s.contains("eyJhbGci"), "{s}");
        assert!(
            s.contains("https://bucket.s3.amazonaws.com/probe/x?…"),
            "{s}"
        );
        assert!(s.contains("denied"));
    }

    #[test]
    fn a_probe_error_is_truncated() {
        let long = "x ".repeat(5_000);
        assert!(scrub(&long).chars().count() <= PROBE_ERROR_MAX);
    }
}
