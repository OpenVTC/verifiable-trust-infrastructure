//! Where this community keeps its rooms' files — `vtc/storage/configs/{list,get,create,
//! update,retire,probe}/0.1`, `vtc/storage/configs/{list,get,create,update}/0.2`,
//! `vtc/storage/credentials/set/0.2`, `vtc/rooms/storage/assign/0.1` and
//! `vtc/rooms/storage/migrate/{0.1,0.2}`
//! (`docs/05-design-notes/data-rooms-files.md` §7; [`crate::rooms::storage_configs`]).
//!
//! The authority is `vtc.rooms.admin`, read from the signer's own entry at execution
//! time: the host's authority over rooms, never a room's. No room-issued credential is
//! required or accepted, and nothing here needs or could use a room key.
//!
//! - **Reads** (`list`, `get`) and the **probe** answer a holder of `vtc.rooms.admin`.
//! - **Changes** (`create`, `update`, `retire`, `assign`, `migrate`) decide where members' files go
//!   and what reaches them, so each is parked for the other holders' consent after the
//!   requester's operation-bound step-up ([`super::acl_tasks::settle_consent_gate`],
//!   [`Act::ChangeStorage`]) and executes itself on the N-th approval, every check
//!   re-run against the community as it is then. A request that would change nothing —
//!   retiring a config already retiring, assigning a room to the config it is on — is
//!   answered at once and parks nothing. So is a `migrate` for a room that already has a
//!   migration `queued`, `running` or `paused` (it answers with that one, resuming a
//!   paused one: it is the same, already approved, migration) or has nothing to move.
//!
//! No member of any of these tasks carries a credential in the clear, and no answer
//! returns one. `vtc/storage/credentials/set/0.2` carries one sealed to this community,
//! which only [`crate::rooms::storage_credentials`] opens.
//!
//! **Versions.** Each version is answered at its own version. 0.2 (trust-tasks-tf #866)
//! adds `roleArn` on `ambient`, the `notAllowed` credential status, and
//! `authNotAllowed`'s `details.reason`; a 0.1 reader is answered in 0.1's shape — a
//! config's `roleArn` left out, and `notAllowed` reported as `required`, its nearest
//! 0.1 status (neither is usable).

use std::collections::HashMap;

use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::rooms::storage::assign::v0_1 as assign;
use trust_tasks_rs::specs::vtc::rooms::storage::migrate::v0_1 as migrate;
use trust_tasks_rs::specs::vtc::rooms::storage::migrate::v0_2 as migrate_v2;
use trust_tasks_rs::specs::vtc::storage::configs::{
    create::v0_1 as create, create::v0_2 as create2, get::v0_1 as get, get::v0_2 as get2,
    list::v0_1 as list, list::v0_2 as list2, probe::v0_1 as probe, retire::v0_1 as retire,
    update::v0_1 as update, update::v0_2 as update2,
};
use trust_tasks_rs::specs::vtc::storage::credentials::set::v0_2 as set;
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::audit::{AuditEvent, RoomStorageChangedData};
use vti_common::auth::extractor::AuthClaims;
use vti_common::blob_store::{BlobKey, PROBE_PREFIX};
use vti_rooms::blobs::{
    ConfigHoldings, Migration, MigrationRequest, MigrationStart, MigrationState,
};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::acl::admin_consent::Act;
use crate::rooms::migration::Wire;
use crate::rooms::storage_configs::{SettingsError, kind_of, mode_of, state_of};
use crate::rooms::storage_credentials::SealedRefusal;
use crate::routes::acl::conform;
use crate::server::AppState;

pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const GET_TYPE: &str = <get::Payload as Payload>::TYPE_URI;
pub(crate) const CREATE_TYPE: &str = <create::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_TYPE: &str = <update::Payload as Payload>::TYPE_URI;
pub(crate) const RETIRE_TYPE: &str = <retire::Payload as Payload>::TYPE_URI;
pub(crate) const PROBE_TYPE: &str = <probe::Payload as Payload>::TYPE_URI;
pub(crate) const ASSIGN_TYPE: &str = <assign::Payload as Payload>::TYPE_URI;
pub(crate) const MIGRATE_TYPE: &str = <migrate::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_V0_2_TYPE: &str = <list2::Payload as Payload>::TYPE_URI;
pub(crate) const GET_V0_2_TYPE: &str = <get2::Payload as Payload>::TYPE_URI;
pub(crate) const CREATE_V0_2_TYPE: &str = <create2::Payload as Payload>::TYPE_URI;
pub(crate) const UPDATE_V0_2_TYPE: &str = <update2::Payload as Payload>::TYPE_URI;
pub(crate) const CREDENTIALS_SET_TYPE: &str = <set::Payload as Payload>::TYPE_URI;
pub(crate) const MIGRATE_V2_TYPE: &str = <migrate_v2::Payload as Payload>::TYPE_URI;

/// Every URI this module routes.
pub(crate) const URIS: &[&str] = &[
    LIST_TYPE,
    GET_TYPE,
    CREATE_TYPE,
    UPDATE_TYPE,
    LIST_V0_2_TYPE,
    GET_V0_2_TYPE,
    CREATE_V0_2_TYPE,
    UPDATE_V0_2_TYPE,
    CREDENTIALS_SET_TYPE,
    RETIRE_TYPE,
    PROBE_TYPE,
    ASSIGN_TYPE,
    MIGRATE_TYPE,
    MIGRATE_V2_TYPE,
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
        LIST_TYPE => handle_list(state, ctx, doc, V::One).await,
        GET_TYPE => handle_get(state, ctx, doc, V::One).await,
        CREATE_TYPE => handle_create(state, ctx, doc, V::One).await,
        UPDATE_TYPE => handle_update(state, ctx, doc, V::One).await,
        LIST_V0_2_TYPE => handle_list(state, ctx, doc, V::Two).await,
        GET_V0_2_TYPE => handle_get(state, ctx, doc, V::Two).await,
        CREATE_V0_2_TYPE => handle_create(state, ctx, doc, V::Two).await,
        UPDATE_V0_2_TYPE => handle_update(state, ctx, doc, V::Two).await,
        CREDENTIALS_SET_TYPE => handle_credentials_set(state, ctx, doc).await,
        RETIRE_TYPE => handle_retire(state, ctx, doc).await,
        PROBE_TYPE => handle_probe(state, ctx, doc).await,
        ASSIGN_TYPE => handle_assign(state, ctx, doc).await,
        MIGRATE_TYPE => handle_migrate(state, ctx, doc, Wire::V0_1).await,
        MIGRATE_V2_TYPE => handle_migrate(state, ctx, doc, Wire::V0_2).await,
        _ => return None,
    })
}

/// The version of a `vtc/storage/configs/*` task being answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V {
    One,
    Two,
}

/// A stored config, as a 0.1 reader may be shown it: 0.1's `ambient` is closed, so
/// `roleArn` is left out.
fn config_at(v: V, mut config: Value) -> Value {
    if v == V::One
        && let Some(auth) = config.get_mut("auth").and_then(Value::as_object_mut)
    {
        auth.remove("roleArn");
    }
    config
}

/// A config's facts at `v`: 0.1 has no `notAllowed`, so a mode the host no longer
/// permits reads as `required` — not usable, in the nearest words 0.1 has.
fn facts_at(v: V, mut facts: Value) -> Value {
    if v == V::One && facts["credential"]["status"] == "notAllowed" {
        facts["credential"] = json!({ "status": "required" });
    }
    facts
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

/// A refusal of proposed settings, under the codes `task` declares. At 0.2,
/// `authNotAllowed` names its reason in `details`; 0.1 declares no details for it.
fn settings_refusal(
    doc: &TrustTask<Value>,
    v: V,
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
        SettingsError::AuthNotAllowed(why, reason) => refuse(
            doc,
            auth_not_allowed,
            reason,
            (v == V::Two).then(|| json!({ "reason": why.as_str() })),
        ),
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
pub(crate) async fn audit(state: &AppState, actor: &str, data: RoomStorageChangedData) {
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

/// The list request's members, read through the version's generated type.
struct ListAsk {
    cursor: Option<String>,
    limit: Option<u64>,
    state: Option<String>,
    kind: Option<String>,
}

/// `vtc/storage/configs/list/{0.1,0.2}` — every config, `retired` ones included, with
/// its facts computed now.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    v: V,
) -> TrustTaskOutcome {
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let checked = match v {
        V::One => match parse_spec_payload::<list::Payload>(&doc) {
            Ok(p) => ListAsk {
                cursor: p.cursor.map(|c| c.to_string()),
                limit: p.limit.map(|l| l.get()),
                state: p.state.map(|s| s.to_string()),
                kind: p.kind.map(|k| k.to_string()),
            },
            Err(reject) => return reject,
        },
        V::Two => match parse_spec_payload::<list2::Payload>(&doc) {
            Ok(p) => ListAsk {
                cursor: p.cursor.map(|c| c.to_string()),
                limit: p.limit.map(|l| l.get()),
                state: p.state.map(|s| s.to_string()),
                kind: p.kind.map(|k| k.to_string()),
            },
            Err(reject) => return reject,
        },
    };
    let invalid_cursor = match v {
        V::One => list::error_codes::INVALID_CURSOR.code,
        V::Two => list2::error_codes::INVALID_CURSOR.code,
    };
    let after = match checked.cursor.as_deref() {
        None => None,
        Some(c) => match c.strip_prefix(CURSOR_PREFIX) {
            Some(id) if !id.is_empty() => Some(id.to_string()),
            _ => {
                return refuse(
                    &doc,
                    invalid_cursor,
                    "that cursor was not issued by this community",
                    None,
                );
            }
        },
    };
    let limit = checked.limit.map(|l| l as usize).unwrap_or(DEFAULT_PAGE);
    let want_state = checked.state;
    let want_kind = checked.kind;

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
        items.push(json!({ "config": config_at(v, config), "facts": facts_at(v, facts) }));
    }
    let mut body = json!({ "items": items });
    if more && let Some(last) = body["items"].as_array().and_then(|i| i.last()) {
        body["nextCursor"] = json!(format!(
            "{CURSOR_PREFIX}{}",
            last["config"]["id"].as_str().unwrap_or_default()
        ));
    }
    match v {
        V::One => respond::<list::Response>(&doc, body),
        V::Two => respond::<list2::Response>(&doc, body),
    }
}

/// `vtc/storage/configs/get/{0.1,0.2}` — one config, its facts and the rooms on it.
async fn handle_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    v: V,
) -> TrustTaskOutcome {
    if let Err(reject) = rooms_admin(state, ctx, &doc).await {
        return reject;
    }
    let (id, not_found) = match v {
        V::One => match parse_spec_payload::<get::Payload>(&doc) {
            Ok(p) => (p.config_id.to_string(), get::error_codes::NOT_FOUND.code),
            Err(reject) => return reject,
        },
        V::Two => match parse_spec_payload::<get2::Payload>(&doc) {
            Ok(p) => (p.config_id.to_string(), get2::error_codes::NOT_FOUND.code),
            Err(reject) => return reject,
        },
    };
    let id = id.as_str();
    let config = match state.room_storage.config(id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return refuse(&doc, not_found, format!("no storage config `{id}`"), None);
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
    let body = json!({
        "config": config_at(v, config),
        "facts": facts_at(v, facts),
        "assignedRoomsTruncated": rooms.len() > ASSIGNED_ROOMS_SHOWN,
        "assignedRooms": rooms.into_iter().take(ASSIGNED_ROOMS_SHOWN).collect::<Vec<_>>(),
    });
    match v {
        V::One => respond::<get::Response>(&doc, body),
        V::Two => respond::<get2::Response>(&doc, body),
    }
}

// ─── create ──────────────────────────────────────────────────────────────

/// The create request's members, read through the version's generated type.
struct CreateAsk {
    id: String,
    label: String,
    capacity_bytes: Option<u64>,
    is_default: Option<bool>,
    reason: String,
}

/// `vtc/storage/configs/create/{0.1,0.2}`.
async fn handle_create(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    v: V,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked = match v {
        V::One => match parse_spec_payload::<create::Payload>(&doc) {
            Ok(p) => CreateAsk {
                id: p.id.to_string(),
                label: p.label.to_string(),
                capacity_bytes: p.capacity_bytes,
                is_default: p.is_default,
                reason: p.reason.to_string(),
            },
            Err(reject) => return reject,
        },
        V::Two => match parse_spec_payload::<create2::Payload>(&doc) {
            Ok(p) => CreateAsk {
                id: p.id.to_string(),
                label: p.label.to_string(),
                capacity_bytes: p.capacity_bytes,
                is_default: p.is_default,
                reason: p.reason.to_string(),
            },
            Err(reject) => return reject,
        },
    };
    let id = checked.id.clone();
    let settings = doc.payload["settings"].clone();
    let auth = doc.payload.get("auth").cloned();

    if let Some(reject) = create_refusal(state, &doc, v, &id, &settings, auth.as_ref(), false).await
    {
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
    if let Some(reject) = create_refusal(state, &doc, v, &id, &settings, auth.as_ref(), true).await
    {
        return reject;
    }
    let mut record = json!({
        "id": id,
        "label": checked.label,
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
            reason: checked.reason.clone(),
        },
    )
    .await;
    // Item 8: probe it once it exists, and record the result as its health. A `sealed`
    // config has no credential yet, and nothing to probe with.
    if state.room_storage.usable(&record) {
        let _ = run_probe(state, &id).await;
    }
    let body = json!({ "config": config_at(v, record) });
    match v {
        V::One => respond::<create::Response>(&doc, body),
        V::Two => respond::<create2::Response>(&doc, body),
    }
}

/// Why a create cannot run now, if it cannot. With `prepare`, a `local` root that passes
/// is also created, owner-only.
async fn create_refusal(
    state: &AppState,
    doc: &TrustTask<Value>,
    v: V,
    id: &str,
    settings: &Value,
    auth: Option<&Value>,
    prepare: bool,
) -> Option<TrustTaskOutcome> {
    let (exists, invalid, not_allowed, unknown) = match v {
        V::One => (
            create::error_codes::EXISTS.code,
            create::error_codes::INVALID_SETTINGS.code,
            create::error_codes::AUTH_NOT_ALLOWED.code,
            create::error_codes::UNKNOWN_ACCOUNT.code,
        ),
        V::Two => (
            create2::error_codes::EXISTS.code,
            create2::error_codes::INVALID_SETTINGS.code,
            create2::error_codes::AUTH_NOT_ALLOWED.code,
            create2::error_codes::UNKNOWN_ACCOUNT.code,
        ),
    };
    match state.room_storage.config(id).await {
        Ok(Some(_)) => {
            return Some(refuse(
                doc,
                exists,
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
        return Some(settings_refusal(doc, v, invalid, not_allowed, unknown, e));
    }
    None
}

// ─── update ──────────────────────────────────────────────────────────────

/// The codes an update refuses with, at its version.
struct UpdateCodes {
    not_found: &'static str,
    kind_immutable: &'static str,
    location_immutable: &'static str,
    invalid: &'static str,
    not_allowed: &'static str,
    unknown: &'static str,
    not_active: &'static str,
}

impl UpdateCodes {
    fn at(v: V) -> Self {
        match v {
            V::One => {
                use update::error_codes as c;
                Self {
                    not_found: c::NOT_FOUND.code,
                    kind_immutable: c::KIND_IMMUTABLE.code,
                    location_immutable: c::LOCATION_IMMUTABLE.code,
                    invalid: c::INVALID_SETTINGS.code,
                    not_allowed: c::AUTH_NOT_ALLOWED.code,
                    unknown: c::UNKNOWN_ACCOUNT.code,
                    not_active: c::NOT_ACTIVE.code,
                }
            }
            V::Two => {
                use update2::error_codes as c;
                Self {
                    not_found: c::NOT_FOUND.code,
                    kind_immutable: c::KIND_IMMUTABLE.code,
                    location_immutable: c::LOCATION_IMMUTABLE.code,
                    invalid: c::INVALID_SETTINGS.code,
                    not_allowed: c::AUTH_NOT_ALLOWED.code,
                    unknown: c::UNKNOWN_ACCOUNT.code,
                    not_active: c::NOT_ACTIVE.code,
                }
            }
        }
    }
}

/// What an update would store, or why it cannot.
async fn plan_update(
    state: &AppState,
    doc: &TrustTask<Value>,
    v: V,
    id: &str,
    prepare: bool,
) -> Result<(Value, Value), TrustTaskOutcome> {
    let c = UpdateCodes::at(v);
    let current = match state.room_storage.config(id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(refuse(
                doc,
                c.not_found,
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
            c.kind_immutable,
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
            c.not_active,
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
                    c.location_immutable,
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
                v,
                c.invalid,
                c.not_allowed,
                c.unknown,
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

/// `vtc/storage/configs/update/{0.1,0.2}`.
async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    v: V,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let (id, reason) = match v {
        V::One => match parse_spec_payload::<update::Payload>(&doc) {
            Ok(p) => (p.config_id.to_string(), p.reason.to_string()),
            Err(reject) => return reject,
        },
        V::Two => match parse_spec_payload::<update2::Payload>(&doc) {
            Ok(p) => (p.config_id.to_string(), p.reason.to_string()),
            Err(reject) => return reject,
        },
    };
    if let Err(reject) = plan_update(state, &doc, v, &id, false).await {
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
    let (previous, mut next) = match plan_update(state, &doc, v, &id, true).await {
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
            reason,
        },
    )
    .await;
    let body = json!({ "config": config_at(v, next) });
    match v {
        V::One => respond::<update::Response>(&doc, body),
        V::Two => respond::<update2::Response>(&doc, body),
    }
}

// ─── credentials ─────────────────────────────────────────────────────────

/// Why a credential cannot be set on `id` now, before anything is opened (item 1):
/// the host does not permit `sealed`, no such config, or one not on `sealed`.
async fn credential_refusal(
    state: &AppState,
    doc: &TrustTask<Value>,
    id: &str,
) -> Result<Value, TrustTaskOutcome> {
    use set::error_codes as c;
    if !state.room_storage.host_auth().sealed {
        return Err(refuse(
            doc,
            c::AUTH_NOT_ALLOWED.code,
            "this community's host does not permit `sealed` authentication; move the config \
             to a permitted mode with vtc/storage/configs/update",
            None,
        ));
    }
    let config = match state.room_storage.config(id).await {
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
    if mode_of(&config) != Some("sealed") {
        return Err(refuse(
            doc,
            c::NOT_SEALED_MODE.code,
            format!(
                "`{id}` does not use `sealed` authentication; a VTA account's credential is \
                 the VTA's, and an ambient config has none"
            ),
            None,
        ));
    }
    Ok(config)
}

/// Open the request's sealed block as `config`'s credential (item 2), refusing under
/// the declared codes. The refusal never quotes the cleartext.
fn open_sealed(
    state: &AppState,
    doc: &TrustTask<Value>,
    config: &Value,
    checked: &set::Payload,
) -> Result<crate::rooms::storage_credentials::OpenedCredential, TrustTaskOutcome> {
    use set::error_codes as c;
    let Some(sealed) = state.room_storage.sealed_credentials() else {
        return Err(app_error_to_reject(
            doc,
            &vti_common::error::AppError::ServiceError {
                status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                message: "this community cannot keep a sealed credential: its signing key is \
                          not loaded"
                    .into(),
            },
        ));
    };
    sealed
        .open(
            checked.config_id.as_str(),
            kind_of(&config["settings"]),
            checked.sealed.as_str(),
            checked.digest_multibase.as_str(),
        )
        .map_err(|e| match e {
            SealedRefusal::CannotOpen(why) => refuse(doc, c::CANNOT_OPEN.code, why, None),
            SealedRefusal::Invalid(why) => refuse(doc, c::INVALID_CREDENTIAL.code, why, None),
        })
}

/// `vtc/storage/credentials/set/0.2`: a `sealed` config's long-lived credential, sealed
/// to this community in the administrator's client. Parked for the other holders'
/// consent like every storage change; on execution every check runs again, the
/// credential replaces (destroys) any before it, the config is probed with it, and the
/// audit trail records its fingerprint — never the credential.
async fn handle_credentials_set(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: set::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = checked.config_id.to_string();
    let config = match credential_refusal(state, &doc, &id).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    if let Err(reject) = open_sealed(state, &doc, &config, &checked) {
        return reject;
    }

    if let Err(reject) = super::acl_tasks::settle_consent_gate(
        state,
        &actor,
        &doc,
        Act::ChangeStorage,
        &id,
        &format!("Set the storage credential of {id}"),
        &format!("Set the storage credential of {id}"),
    )
    .await
    {
        return reject;
    }

    let guard = state.room_storage.lock().await;
    let config = match credential_refusal(state, &doc, &id).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let opened = match open_sealed(state, &doc, &config, &checked) {
        Ok(o) => o,
        Err(reject) => return reject,
    };
    let Some(sealed) = state.room_storage.sealed_credentials() else {
        return app_error_to_reject(
            &doc,
            &vti_common::error::AppError::Internal("sealed credentials went away".into()),
        );
    };
    let previous = sealed.get(&id).await.ok().flatten().map(|c| c.fingerprint);
    let stored = match sealed.put(&id, opened).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // A fresh backend over the new credential; every room-scoped credential minted from
    // the old one goes with the old backend.
    if let Err(e) = state.room_storage.put_config(config.clone()).await {
        return app_error_to_reject(&doc, &e);
    }
    drop(guard);

    audit(
        state,
        &actor.did,
        RoomStorageChangedData {
            event: "credentialSet".into(),
            config_id: id.clone(),
            room_id: None,
            previous: previous.map(|f| json!({ "fingerprint": f })),
            current: json!({ "fingerprint": stored.fingerprint, "setAt": stored.set_at }),
            approvers: crate::admin_actions::executing_approvers(state).await,
            reason: checked.reason.to_string(),
        },
    )
    .await;
    // Item 6: probe with the new credential, and say how it went.
    let probe_ok = run_probe(state, &id)
        .await
        .ok()
        .and_then(|p| p["ok"].as_bool());
    let credential_state = match state.room_storage.credential_state(&config).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut body = json!({ "configId": id, "credentialState": credential_state });
    if let Some(ok) = probe_ok {
        body["probeOk"] = json!(ok);
    }
    respond::<set::Response>(&doc, body)
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

// ─── migrate ─────────────────────────────────────────────────────────────

/// Why the room's files cannot be moved to `config_id` now (`migrate` item 1), if they
/// cannot.
async fn check_target(
    state: &AppState,
    doc: &TrustTask<Value>,
    config_id: &str,
) -> Result<Option<u64>, TrustTaskOutcome> {
    use migrate::error_codes as c;
    let config = match state.room_storage.config(config_id).await {
        Ok(c) => c,
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    let Some(config) = config else {
        return Err(refuse(
            doc,
            c::CONFIG_NOT_ACTIVE.code,
            "this room is assigned to no storage config; assign it to an active one first",
            None,
        ));
    };
    if state_of(&config) != "active" {
        return Err(refuse(
            doc,
            c::CONFIG_NOT_ACTIVE.code,
            format!(
                "`{config_id}` is {} and takes no files; assign the room to an active config \
                 first",
                state_of(&config)
            ),
            None,
        ));
    }
    if !state.room_storage.usable(&config) {
        return Err(refuse(
            doc,
            c::CONFIG_NOT_ACTIVE.code,
            format!("`{config_id}` has no usable credential, so it cannot receive the files"),
            None,
        ));
    }
    Ok(config["capacityBytes"].as_u64())
}

fn capacity_refusal(
    doc: &TrustTask<Value>,
    config_id: &str,
    capacity: u64,
    used: u64,
    requested: u64,
) -> TrustTaskOutcome {
    refuse(
        doc,
        migrate::error_codes::CAPACITY_EXCEEDED.code,
        format!(
            "`{config_id}` cannot hold the {requested} bytes to move: {used} of its {capacity} \
             bytes are in use"
        ),
        Some(json!({
            "capacityBytes": capacity,
            "usedBytes": used,
            "requestedBytes": requested,
        })),
    )
}

/// The request as both versions state it: 0.2's request is 0.1's unchanged.
struct MigrateAsk {
    room_id: String,
    reason: String,
    max_bytes_per_second: Option<u64>,
}

fn parse_migrate(doc: &TrustTask<Value>, wire: Wire) -> Result<MigrateAsk, TrustTaskOutcome> {
    let rate = |v: Option<i64>| v.map(|v| v.max(0) as u64);
    Ok(match wire {
        Wire::V0_1 => {
            let p: migrate::Payload = parse_spec_payload(doc)?;
            MigrateAsk {
                room_id: p.room_id.as_str().to_string(),
                reason: p.reason.as_str().to_string(),
                max_bytes_per_second: rate(p.max_bytes_per_second),
            }
        }
        Wire::V0_2 => {
            let p: migrate_v2::Payload = parse_spec_payload(doc)?;
            MigrateAsk {
                room_id: p.room_id.as_str().to_string(),
                reason: p.reason.as_str().to_string(),
                max_bytes_per_second: rate(p.max_bytes_per_second),
            }
        }
    })
}

/// The migration, as `wire`'s `#response`.
fn migrate_answer(doc: &TrustTask<Value>, m: &Migration, wire: Wire) -> TrustTaskOutcome {
    let body = crate::rooms::migration::response_json(m, wire);
    match wire {
        Wire::V0_1 => respond::<migrate::Response>(doc, body),
        Wire::V0_2 => respond::<migrate_v2::Response>(doc, body),
    }
}

/// `vtc/rooms/storage/migrate/0.1` and `/0.2`: move a room's existing blobs onto its
/// assigned config (`data-rooms-files.md` §7.3). The work is the migration runner's
/// ([`crate::rooms::migration`]); this answers with the migration and its progress so far.
/// Both versions drive one engine and are answered each at its own version; 0.2 states
/// what 0.1 left open (reassignment, retry ownership, resumption, orphans, pause
/// reporting, queueing), and this host behaves the 0.2 way whichever is asked. The
/// declared error codes are the same three at both versions.
async fn handle_migrate(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    wire: Wire,
) -> TrustTaskOutcome {
    use migrate::error_codes as c;
    let actor = match rooms_admin(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let ask = match parse_migrate(&doc, wire) {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let room_id = ask.room_id;
    let reason = ask.reason;

    match vti_rooms::storage::get_room(&state.rooms_ks, &room_id).await {
        Ok(_) => {}
        Err(vti_common::error::AppError::NotFound(_)) => {
            return refuse(
                &doc,
                c::ROOM_NOT_FOUND.code,
                "this community hosts no such room",
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    // Item 5: a migration queued, running or paused is the answer — a paused one
    // resumed at once — and nothing is parked again for it: its approvers agreed to it
    // when it started. Its target and reason stand (item 9), whatever the room is
    // assigned to now and whatever this request says; its rate may be the request's.
    match state.room_files.migration(&room_id).await {
        Ok(Some(m)) if m.state.is_open() => {
            let mut again = MigrationRequest::new(room_id, m.to_config, &actor.did, m.reason);
            again.max_bytes_per_second = ask.max_bytes_per_second;
            return start(state, &doc, &actor.did, again, wire).await;
        }
        Ok(_) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    let to_config = match super::room_admin_tasks::assigned_config(state, &room_id).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let capacity = match check_target(state, &doc, &to_config).await {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let plan = match state.room_files.plan_migration(&room_id, &to_config).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // Item 2, before anything is parked or copied.
    if let Some(cap) = capacity
        && plan.bytes > 0
    {
        let used = match state.room_files.config_used_bytes(&to_config).await {
            Ok(u) => u,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if used + plan.bytes > cap {
            return capacity_refusal(&doc, &to_config, cap, used, plan.bytes);
        }
    }
    let mut req = MigrationRequest::new(&room_id, &to_config, &actor.did, &reason);
    req.capacity_bytes = capacity;
    req.max_bytes_per_second = ask.max_bytes_per_second;

    // Item 7: nothing to move completes at once and changes nothing, so parks nothing.
    if plan.files > 0 {
        let summary = format!("Move room {room_id}'s files to {to_config}");
        if let Err(reject) = super::acl_tasks::settle_consent_gate(
            state,
            &actor,
            &doc,
            Act::ChangeStorage,
            &room_id,
            &summary,
            &summary,
        )
        .await
        {
            return reject;
        }
        // Executing: every check again, against the community as it is now.
        req.to_config = match super::room_admin_tasks::assigned_config(state, &room_id).await {
            Ok(c) => c,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        req.capacity_bytes = match check_target(state, &doc, &req.to_config).await {
            Ok(c) => c,
            Err(reject) => return reject,
        };
        req.approvers = crate::admin_actions::executing_approvers(state).await;
    }
    start(state, &doc, &actor.did, req, wire).await
}

/// Start, or resume, the migration `req` describes, audit what changed and wake the
/// runner. Under the host's lock a migration approved meanwhile for the same room is
/// the answer instead (item 5).
async fn start(
    state: &AppState,
    doc: &TrustTask<Value>,
    actor: &str,
    req: MigrationRequest,
    wire: Wire,
) -> TrustTaskOutcome {
    let to_config = req.to_config.clone();
    let outcome = match state.room_files.start_migration(req).await {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let m = match outcome {
        MigrationStart::Started(m) => {
            crate::rooms::migration::audit_migration(state, &m, "migrationStarted", actor).await;
            if m.state == MigrationState::Complete {
                crate::rooms::migration::audit_migration(state, &m, "migrationCompleted", actor)
                    .await;
            }
            m
        }
        MigrationStart::Resumed(m) => {
            crate::rooms::migration::audit_migration(state, &m, "migrationResumed", actor).await;
            m
        }
        MigrationStart::InProgress(m) => m,
        MigrationStart::CapacityExceeded {
            capacity,
            used,
            requested,
        } => return capacity_refusal(doc, &to_config, capacity, used, requested),
        _ => {
            return app_error_to_reject(
                doc,
                &vti_common::error::AppError::Internal("unexpected migration outcome".into()),
            );
        }
    };
    if matches!(m.state, MigrationState::Running | MigrationState::Queued) {
        crate::rooms::migration::kick();
    }
    migrate_answer(doc, &m, wire)
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
