//! The community's events on the signed-document spine (`vtc/events/*`, VTI-EVT-001 – 095;
//! [`crate::community_events`]).
//!
//! | task | authority (read now) |
//! |---|---|
//! | `calendars/{create,update}/0.1` | the calendar's authority: `vtc.events.manage` unqualified, or for a group's calendar at `group:<id>` or managing the group (VTI-EVT-013) |
//! | `calendars/list/0.1` | an active member, or a holder of `vtc.events.manage` |
//! | `create/0.1` | the calendar's authority |
//! | `update`, `publish`, `cancel`, `delete/0.1` | the event's hosts: the calendar's authority or an appointed host (VTI-EVT-070) — never a portal key |
//! | `show`, `list/0.1`, `access/show/0.1`, `hosts/list/0.1` | the event's audience, a registrant, or a host |
//! | `mine/list/0.1` | the caller, as themselves |
//! | `registrations/{register,withdraw}/0.1` | the registrant |
//! | `registrations/list/0.1` | hosts (every registration), or a registrant on a `visible` roster |
//! | `registrations/{decide,remove}/0.1`, `hosts/{appoint,remove}/0.1` | the event's hosts — never a portal key |
//! | `report/0.1` | a member of the event's audience |
//!
//! Member acts accept a document signed by the portal's sign-in key for the member's live
//! session (`member_portal::delegation`, VTI-EVT-095); host acts take the signer's own key only.
//! An event or calendar the caller may not see is `notFound`, as one that does not exist
//! (VTI-EVT-023). None has a REST route.

use super::routing::{Routes, on};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vtc_audit::{AuditEvent, EventChangedData};
use vti_common::error::AppError;
use vti_specs::vtc::events::{
    access::show::v0_1 as access_show,
    calendars::{create::v0_1 as cal_create, list::v0_1 as cal_list, update::v0_1 as cal_update},
    cancel::v0_1 as ev_cancel,
    create::v0_1 as ev_create,
    delete::v0_1 as ev_delete,
    hosts::{
        appoint::v0_1 as hosts_appoint, list::v0_1 as hosts_list, remove::v0_1 as hosts_remove,
    },
    list::v0_1 as ev_list,
    mine::list::v0_1 as mine_list,
    publish::v0_1 as ev_publish,
    registrations::{
        decide::v0_1 as reg_decide, list::v0_1 as reg_list, register::v0_1 as reg_register,
        remove::v0_1 as reg_remove, withdraw::v0_1 as reg_withdraw,
    },
    report::v0_1 as ev_report,
    show::v0_1 as ev_show,
    update::v0_1 as ev_update,
};

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::community_events::{
    self as ce, Calendar, CalendarState, EventRecord, Lifecycle, Mode, RegStatus, Registration,
    Report, Roster, Viewer, When, WhenError, hosts,
};
use crate::server::AppState;

macro_rules! codes {
    ($($name:ident = $module:ident :: $code:ident;)*) => {
        $(pub(crate) const $name: &str = $module::error_codes::$code.code;)*
    };
}

codes! {
    CAL_CREATE_ERR_EVENTS_OFF = cal_create::EVENTS_OFF;
    CAL_CREATE_ERR_GROUP_NOT_FOUND = cal_create::GROUP_NOT_FOUND;
    CAL_CREATE_ERR_GROUP_HAS_CALENDAR = cal_create::GROUP_HAS_CALENDAR;
    CAL_CREATE_ERR_SETTINGS_INVALID = cal_create::SETTINGS_INVALID;
    CAL_UPDATE_ERR_EVENTS_OFF = cal_update::EVENTS_OFF;
    CAL_UPDATE_ERR_COMMUNITY_CALENDAR = cal_update::COMMUNITY_CALENDAR;
    CAL_UPDATE_ERR_GROUP_HAS_CALENDAR = cal_update::GROUP_HAS_CALENDAR;
    CAL_UPDATE_ERR_SETTINGS_INVALID = cal_update::SETTINGS_INVALID;
    CREATE_ERR_EVENTS_OFF = ev_create::EVENTS_OFF;
    CREATE_ERR_CALENDAR_ARCHIVED = ev_create::CALENDAR_ARCHIVED;
    CREATE_ERR_TIME_ZONE_UNKNOWN = ev_create::TIME_ZONE_UNKNOWN;
    CREATE_ERR_WHEN_INVALID = ev_create::WHEN_INVALID;
    CREATE_ERR_AUDIENCE_INVALID = ev_create::AUDIENCE_INVALID;
    CREATE_ERR_REGISTRATION_INVALID = ev_create::REGISTRATION_INVALID;
    CREATE_ERR_POLICY_REFUSED = ev_create::POLICY_REFUSED;
    UPDATE_ERR_EVENTS_OFF = ev_update::EVENTS_OFF;
    UPDATE_ERR_EVENT_CANCELLED = ev_update::EVENT_CANCELLED;
    UPDATE_ERR_ROSTER_LOCKED = ev_update::ROSTER_LOCKED;
    UPDATE_ERR_TIME_ZONE_UNKNOWN = ev_update::TIME_ZONE_UNKNOWN;
    UPDATE_ERR_WHEN_INVALID = ev_update::WHEN_INVALID;
    UPDATE_ERR_AUDIENCE_INVALID = ev_update::AUDIENCE_INVALID;
    UPDATE_ERR_REGISTRATION_INVALID = ev_update::REGISTRATION_INVALID;
    UPDATE_ERR_POLICY_REFUSED = ev_update::POLICY_REFUSED;
    PUBLISH_ERR_EVENTS_OFF = ev_publish::EVENTS_OFF;
    PUBLISH_ERR_NOT_DRAFT = ev_publish::NOT_DRAFT;
    PUBLISH_ERR_CALENDAR_ARCHIVED = ev_publish::CALENDAR_ARCHIVED;
    PUBLISH_ERR_EVENT_ENDED = ev_publish::EVENT_ENDED;
    PUBLISH_ERR_POLICY_REFUSED = ev_publish::POLICY_REFUSED;
    CANCEL_ERR_EVENTS_OFF = ev_cancel::EVENTS_OFF;
    CANCEL_ERR_NOT_PUBLISHED = ev_cancel::NOT_PUBLISHED;
    CANCEL_ERR_EVENT_ENDED = ev_cancel::EVENT_ENDED;
    DELETE_ERR_EVENTS_OFF = ev_delete::EVENTS_OFF;
    DELETE_ERR_NOT_DRAFT = ev_delete::NOT_DRAFT;
    LIST_ERR_RANGE_INVALID = ev_list::RANGE_INVALID;
    ACCESS_ERR_NOT_GOING = access_show::NOT_GOING;
    ACCESS_ERR_NOT_YET = access_show::NOT_YET;
    ACCESS_ERR_EVENT_CANCELLED = access_show::EVENT_CANCELLED;
    REGISTER_ERR_NOT_OPEN = reg_register::NOT_OPEN;
    REGISTER_ERR_EVENT_CANCELLED = reg_register::EVENT_CANCELLED;
    REGISTER_ERR_WINDOW_CLOSED = reg_register::WINDOW_CLOSED;
    REGISTER_ERR_FULL = reg_register::FULL;
    REGISTER_ERR_TOO_MANY_GUESTS = reg_register::TOO_MANY_GUESTS;
    REGISTER_ERR_ANSWERS_INVALID = reg_register::ANSWERS_INVALID;
    REGISTER_ERR_CODE_OF_CONDUCT_REQUIRED = reg_register::CODE_OF_CONDUCT_REQUIRED;
    REGISTER_ERR_MAYBE_NOT_ACCEPTED = reg_register::MAYBE_NOT_ACCEPTED;
    REGISTER_ERR_HOST_DECIDED = reg_register::HOST_DECIDED;
    WITHDRAW_ERR_NOT_REGISTERED = reg_withdraw::NOT_REGISTERED;
    REG_LIST_ERR_ROSTER_HIDDEN = reg_list::ROSTER_HIDDEN;
    REG_LIST_ERR_NOT_REGISTERED = reg_list::NOT_REGISTERED;
    REG_LIST_ERR_FILTER_NOT_PERMITTED = reg_list::FILTER_NOT_PERMITTED;
    DECIDE_ERR_NOT_PENDING = reg_decide::NOT_PENDING;
    DECIDE_ERR_FULL = reg_decide::FULL;
    DECIDE_ERR_EVENT_CANCELLED = reg_decide::EVENT_CANCELLED;
    REMOVE_ERR_EVENT_ENDED = reg_remove::EVENT_ENDED;
    APPOINT_ERR_NOT_ELIGIBLE = hosts_appoint::NOT_ELIGIBLE;
    APPOINT_ERR_ALREADY_HOST = hosts_appoint::ALREADY_HOST;
    APPOINT_ERR_EVENT_CANCELLED = hosts_appoint::EVENT_CANCELLED;
    HOSTS_REMOVE_ERR_NOT_HOST = hosts_remove::NOT_HOST;
    HOSTS_REMOVE_ERR_LAST_HOST = hosts_remove::LAST_HOST;
    REPORT_ERR_ALREADY_REPORTED = ev_report::ALREADY_REPORTED;
    REPORT_ERR_LIMIT_REACHED = ev_report::LIMIT_REACHED;
}

/// Register every task this family serves.
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, cal_create::Payload => |state, ctx, doc| handle_calendar_create(state, ctx, doc));
    let routes = on!(routes, cal_update::Payload => |state, ctx, doc| handle_calendar_update(state, ctx, doc));
    let routes =
        on!(routes, cal_list::Payload => |state, ctx, doc| handle_calendar_list(state, ctx, doc));
    let routes =
        on!(routes, ev_create::Payload => |state, ctx, doc| handle_create(state, ctx, doc));
    let routes =
        on!(routes, ev_update::Payload => |state, ctx, doc| handle_update(state, ctx, doc));
    let routes =
        on!(routes, ev_publish::Payload => |state, ctx, doc| handle_publish(state, ctx, doc));
    let routes =
        on!(routes, ev_cancel::Payload => |state, ctx, doc| handle_cancel(state, ctx, doc));
    let routes =
        on!(routes, ev_delete::Payload => |state, ctx, doc| handle_delete(state, ctx, doc));
    let routes = on!(routes, ev_show::Payload => |state, ctx, doc| handle_show(state, ctx, doc));
    let routes = on!(routes, ev_list::Payload => |state, ctx, doc| handle_list(state, ctx, doc));
    let routes = on!(routes, mine_list::Payload => |state, ctx, doc| handle_mine(state, ctx, doc));
    let routes =
        on!(routes, access_show::Payload => |state, ctx, doc| handle_access(state, ctx, doc));
    let routes =
        on!(routes, reg_register::Payload => |state, ctx, doc| handle_register(state, ctx, doc));
    let routes =
        on!(routes, reg_withdraw::Payload => |state, ctx, doc| handle_withdraw(state, ctx, doc));
    let routes =
        on!(routes, reg_list::Payload => |state, ctx, doc| handle_registrations(state, ctx, doc));
    let routes =
        on!(routes, reg_decide::Payload => |state, ctx, doc| handle_decide(state, ctx, doc));
    let routes =
        on!(routes, reg_remove::Payload => |state, ctx, doc| handle_remove(state, ctx, doc));
    let routes = on!(routes, hosts_appoint::Payload => |state, ctx, doc| handle_hosts_appoint(state, ctx, doc));
    let routes = on!(routes, hosts_remove::Payload => |state, ctx, doc| handle_hosts_remove(state, ctx, doc));
    let routes =
        on!(routes, hosts_list::Payload => |state, ctx, doc| handle_hosts_list(state, ctx, doc));
    on!(routes, ev_report::Payload => |state, ctx, doc| handle_report(state, ctx, doc))
}

// ─── shared ──────────────────────────────────────────────────────────────

type Doc = TrustTask<Value>;

fn declared(doc: &Doc, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

fn declared_with(
    doc: &Doc,
    code: &str,
    message: impl Into<String>,
    details: Value,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, Some(details))
}

fn denied(doc: &Doc, why: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: why.to_string(),
        },
    )
}

fn not_found(doc: &Doc, what: &str) -> TrustTaskOutcome {
    app_error_to_reject(
        doc,
        &AppError::NotFound(format!("no {what} you may see has this identifier")),
    )
}

fn malformed(doc: &Doc, why: &str) -> TrustTaskOutcome {
    app_error_to_reject(doc, &AppError::Validation(why.to_string()))
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

macro_rules! tri {
    ($doc:expr, $e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return app_error_to_reject($doc, &e),
        }
    };
}

/// A member's act: the signer's own key, or the portal's key for the member's live session
/// (VTI-EVT-095).
async fn member(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &Doc,
) -> Result<Viewer, TrustTaskOutcome> {
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
    Viewer::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// A host's act: the signer's own key only — never the portal's delegated key (VTI-EVT-095).
async fn host_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &Doc,
) -> Result<Viewer, TrustTaskOutcome> {
    let did = member_signer(state, ctx, doc).await?.did;
    Viewer::read(state, &did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// An event change is never unaudited (VTI-EVT-091).
async fn audit(state: &AppState, actor: &str, data: EventChangedData) -> Result<(), AppError> {
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured: event changes are refused rather than made \
                      unaudited"
                .into(),
        })?;
    writer
        .write(actor, None, AuditEvent::EventChanged(data))
        .await
        .map(drop)
}

fn change(change: &str) -> EventChangedData {
    EventChangedData {
        event_id: None,
        calendar_id: None,
        registration_id: None,
        entry_id: None,
        change: change.to_string(),
        fields: Vec::new(),
    }
}

fn event_change(ev: &str, what: &str) -> EventChangedData {
    EventChangedData {
        event_id: Some(ev.to_string()),
        ..change(what)
    }
}

fn reg_change(reg: &Registration, what: &str) -> EventChangedData {
    EventChangedData {
        event_id: Some(reg.event_id.clone()),
        registration_id: Some(reg.registration_id.clone()),
        entry_id: Some(reg.entry_id.clone()),
        fields: vec![reg.status.as_str().to_string()],
        ..change(what)
    }
}

async fn events_on(state: &AppState) -> bool {
    state.config.read().await.events.enabled
}

/// The caller's directory entry, made if they have none yet (as groups and boards do).
async fn own_entry(state: &AppState, who: &Viewer) -> Result<String, AppError> {
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

async fn schema(state: &AppState) -> Result<Vec<crate::directory::model::FieldDef>, AppError> {
    crate::directory::fields::schema(state.directory.ks()).await
}

// ── paging ──

const CURSOR_FAMILY: &str = "vtc/events";

fn limit_of(payload: &Value, max: usize) -> usize {
    payload
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(50, |l| l as usize)
        .clamp(1, max)
}

/// The page of `all` the payload's cursor names, and the next cursor.
async fn page<T: Clone>(
    state: &AppState,
    doc: &Doc,
    binding: &str,
    all: &[T],
    max: usize,
) -> Result<(Vec<T>, Option<String>), TrustTaskOutcome> {
    let key = super::offset_cursor::key(state)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let start = match str_of(&doc.payload, "cursor") {
        None => 0,
        Some(c) => super::offset_cursor::read(&key, CURSOR_FAMILY, binding, c)
            .ok_or_else(|| malformed(doc, "this cursor is not this caller's for these filters"))?,
    };
    let (start, end) = super::offset_cursor::window(start, limit_of(&doc.payload, max), all.len());
    let next =
        (end < all.len()).then(|| super::offset_cursor::mint(&key, CURSOR_FAMILY, binding, end));
    Ok((all[start..end].to_vec(), next))
}

// ── reading an event as a caller ──

/// An event and what the caller is to it.
struct Seen {
    ev: EventRecord,
    cal: Option<Calendar>,
    host: bool,
    own: Option<Registration>,
}

/// The event `id` as `who` may see it: hosts always; a draft only hosts; otherwise its
/// audience (checked live, VTI-EVT-021) or a holder of a registration for it. `None` is
/// `notFound` (VTI-EVT-023).
async fn visible_event(state: &AppState, who: &Viewer, id: &str) -> Result<Option<Seen>, AppError> {
    if !events_on(state).await {
        return Ok(None);
    }
    let ks = &state.events_ks;
    let Some(ev) = ce::get_event(ks, id).await? else {
        return Ok(None);
    };
    let cal = ce::get_calendar(ks, &ev.calendar_id).await?;
    let host = who.hosts(&ev, cal.as_ref());
    let own = match &who.entry_id {
        Some(e) => ce::get_registration(ks, id, e).await?,
        None => None,
    };
    if host {
        return Ok(Some(Seen { ev, cal, host, own }));
    }
    if ev.status == Lifecycle::Draft {
        return Ok(None);
    }
    let schema = schema(state).await?;
    let sees = own.is_some() || who.in_audience(&ev.audience, &schema);
    Ok(sees.then_some(Seen { ev, cal, host, own }))
}

/// The event as `seen` may see it, with its hosts.
async fn wire_for(state: &AppState, seen: &Seen) -> Result<Value, AppError> {
    let regs = ce::registrations_of(&state.events_ks, &seen.ev.event_id).await?;
    let hosts = hosts::entries(state, &seen.ev.event_id).await?;
    Ok(ce::event_wire(&seen.ev, seen.host, &regs, &hosts))
}

async fn event_answer(state: &AppState, doc: &Doc, seen: &Seen) -> TrustTaskOutcome {
    match wire_for(state, seen).await {
        Ok(w) => success_response(doc, json!({ "event": w })),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

// ── the event's own checks (VTI-EVT-005, 020, 031 – 036) ──

enum Invalid {
    TimeZone(String),
    When(String),
    Audience(String),
    Registration(String, String),
}

fn check_when(when: &When) -> Result<(), Invalid> {
    match when.interval() {
        Ok(_) => Ok(()),
        Err(WhenError::TimeZoneUnknown(z)) => Err(Invalid::TimeZone(z)),
        Err(WhenError::Invalid(m)) => Err(Invalid::When(m)),
    }
}

async fn check_audience(
    state: &AppState,
    audience: &Value,
    schema: &[crate::directory::model::FieldDef],
) -> Result<Result<(), Invalid>, AppError> {
    let names = |k: &str| -> Vec<String> {
        audience
            .get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let scope = str_of(audience, "scope").unwrap_or_default();
    let groups = names("groups");
    let roles = names("roles");
    match scope {
        "members" if groups.is_empty() && roles.is_empty() => {}
        "groups" if !groups.is_empty() && roles.is_empty() => {
            for g in &groups {
                if crate::groups::get(state.directory.ks(), g).await?.is_none() {
                    return Ok(Err(Invalid::Audience(format!("no group {g}"))));
                }
            }
        }
        "roles" if !roles.is_empty() && groups.is_empty() => {}
        _ => {
            return Ok(Err(Invalid::Audience(
                "`groups` is present exactly when the scope is `groups`, `roles` exactly when it \
                 is `roles`"
                    .into(),
            )));
        }
    }
    if let Some(rule) = audience.get("rule")
        && let Err(e) = crate::groups::check_rule(rule, schema)
    {
        return Ok(Err(Invalid::Audience(format!("the rule: {}", e.reason))));
    }
    Ok(Ok(()))
}

fn check_registration(registration: &Value) -> Result<(), Invalid> {
    let bad = |field: &str, reason: &str| Invalid::Registration(field.into(), reason.into());
    let s = ce::Settings::read(registration);
    if s.waitlist && s.capacity.is_none() {
        return Err(bad("waitlist", "a waitlist needs a capacity"));
    }
    if let (Some(o), Some(c)) = (s.opens_at, s.closes_at)
        && o >= c
    {
        return Err(bad("closesAt", "registrations close after they open"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for q in &s.questions {
        let id = str_of(q, "questionId").unwrap_or_default();
        if !ids.insert(id.to_string()) {
            return Err(bad("questions", &format!("question {id} is named twice")));
        }
        let choice = str_of(q, "kind") == Some("choice");
        if choice != q.get("choices").is_some() {
            return Err(bad(
                "questions",
                &format!("question {id}: `choices` is present exactly for a choice"),
            ));
        }
    }
    Ok(())
}

fn refuse_invalid(
    doc: &Doc,
    inv: Invalid,
    tz: &str,
    when: &str,
    audience: &str,
    registration: &str,
) -> TrustTaskOutcome {
    match inv {
        Invalid::TimeZone(z) => declared_with(
            doc,
            tz,
            format!("{z} is not a time zone this community knows."),
            json!({ "timeZone": z }),
        ),
        Invalid::When(m) => declared(doc, when, m),
        Invalid::Audience(m) => {
            declared(doc, audience, format!("The audience is not usable: {m}."))
        }
        Invalid::Registration(field, reason) => declared_with(
            doc,
            registration,
            format!("The registration settings are not usable: {reason}."),
            json!({ "field": field, "reason": reason }),
        ),
    }
}

/// VTI-EVT-080: the community's `events` policy, asked last.
async fn policy_refusal(
    state: &AppState,
    who: &Viewer,
    operation: &'static str,
    cal: &Calendar,
    ev: &EventRecord,
    event_id: &str,
) -> Result<Option<String>, AppError> {
    let role = who.subject.as_ref().map(|s| s.role.clone());
    ce::policy::decide(
        state,
        &ce::policy::Facts {
            operation,
            now: Utc::now(),
            actor_did: &who.did,
            actor_role: role.as_deref(),
            actor_runs_all: who.runs_all(),
            calendar: cal,
            event: ev,
            event_id,
        },
    )
    .await
}

fn reminders(v: &Value, key: &str) -> Option<Vec<u32>> {
    v.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_u64)
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
            .collect()
    })
}

// ─── calendars ───────────────────────────────────────────────────────────

async fn handle_calendar_create(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<cal_create::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            CAL_CREATE_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let p = &doc.payload;
    let group_id = str_of(p, "groupId").map(str::to_string);
    let draft = Calendar {
        calendar_id: ce::new_calendar_id(),
        name: str_of(p, "name").unwrap_or_default().to_string(),
        description: str_of(p, "description").map(str::to_string),
        color: str_of(p, "color").map(str::to_string),
        group_id: group_id.clone(),
        community: false,
        default_roster: str_of(p, "defaultRoster").and_then(Roster::parse),
        default_reminder_minutes: reminders(p, "defaultReminderMinutes").unwrap_or_default(),
        state: CalendarState::Active,
        created_at: Utc::now(),
    };
    // VTI-EVT-013: who runs it.
    if !who.runs_calendar(&draft) {
        return denied(
            &doc,
            "a calendar is made by holders of vtc.events.manage, or a group's by those who run \
             its events",
        );
    }
    // A name of nothing but spaces is malformed, though the schema's length admits it.
    if draft.name.trim().is_empty() {
        return declared_with(
            &doc,
            CAL_CREATE_ERR_SETTINGS_INVALID,
            "A calendar's name says something.",
            json!({ "field": "name", "reason": "blank" }),
        );
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    if let Some(g) = &group_id {
        // VTI-EVT-012.
        if tri!(&doc, crate::groups::get(state.directory.ks(), g).await).is_none() {
            return declared(
                &doc,
                CAL_CREATE_ERR_GROUP_NOT_FOUND,
                format!("There is no group {g}."),
            );
        }
        if tri!(&doc, ce::group_calendar(&state.events_ks, g).await).is_some() {
            return declared(
                &doc,
                CAL_CREATE_ERR_GROUP_HAS_CALENDAR,
                "This group already has a calendar.",
            );
        }
    }
    if draft.default_reminder_minutes.len()
        != draft
            .default_reminder_minutes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    {
        return declared_with(
            &doc,
            CAL_CREATE_ERR_SETTINGS_INVALID,
            "Each reminder is named once.",
            json!({ "field": "defaultReminderMinutes", "reason": "duplicate" }),
        );
    }
    // The community's own calendar exists before any other (VTI-EVT-011).
    tri!(&doc, ce::community_calendar(&state.events_ks).await);
    tri!(&doc, ce::put_calendar(&state.events_ks, &draft).await);
    drop(_guard);
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                calendar_id: Some(draft.calendar_id.clone()),
                ..change("calendarCreated")
            }
        )
        .await
    );
    success_response(&doc, json!({ "calendar": ce::calendar_wire(&draft) }))
}

async fn handle_calendar_update(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<cal_update::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            CAL_UPDATE_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let p = &doc.payload;
    let id = str_of(p, "calendarId").unwrap_or_default();
    let _guard = ce::WRITE_LOCK.lock().await;
    let Some(mut cal) = tri!(&doc, ce::get_calendar(&state.events_ks, id).await) else {
        return not_found(&doc, "calendar");
    };
    if !who.runs_calendar(&cal) {
        return not_found(&doc, "calendar");
    }
    let mut fields = Vec::new();
    if let Some(n) = str_of(p, "name") {
        if n.trim().is_empty() {
            return declared_with(
                &doc,
                CAL_UPDATE_ERR_SETTINGS_INVALID,
                "A calendar's name says something.",
                json!({ "field": "name", "reason": "blank" }),
            );
        }
        cal.name = n.to_string();
        fields.push("name".to_string());
    }
    for (key, slot) in [
        ("description", &mut cal.description),
        ("color", &mut cal.color),
    ] {
        if let Some(v) = p.get(key) {
            *slot = v.as_str().map(str::to_string);
            fields.push(key.to_string());
        }
    }
    if let Some(r) = str_of(p, "defaultRoster") {
        cal.default_roster = Roster::parse(r);
        fields.push("defaultRoster".into());
    }
    if let Some(r) = reminders(p, "defaultReminderMinutes") {
        if r.len() != r.iter().collect::<std::collections::BTreeSet<_>>().len() {
            return declared_with(
                &doc,
                CAL_UPDATE_ERR_SETTINGS_INVALID,
                "Each reminder is named once.",
                json!({ "field": "defaultReminderMinutes", "reason": "duplicate" }),
            );
        }
        cal.default_reminder_minutes = r;
        fields.push("defaultReminderMinutes".into());
    }
    if let Some(s) = str_of(p, "state") {
        let to = if s == "archived" {
            CalendarState::Archived
        } else {
            CalendarState::Active
        };
        if to == CalendarState::Archived && cal.community {
            // VTI-EVT-011.
            return declared(
                &doc,
                CAL_UPDATE_ERR_COMMUNITY_CALENDAR,
                "The community's own calendar is never archived.",
            );
        }
        if to == CalendarState::Active
            && cal.state == CalendarState::Archived
            && let Some(g) = &cal.group_id
            && tri!(&doc, ce::group_calendar(&state.events_ks, g).await).is_some()
        {
            return declared(
                &doc,
                CAL_UPDATE_ERR_GROUP_HAS_CALENDAR,
                "This group already has an active calendar.",
            );
        }
        cal.state = to;
        fields.push("state".into());
    }
    tri!(&doc, ce::put_calendar(&state.events_ks, &cal).await);
    drop(_guard);
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                calendar_id: Some(cal.calendar_id.clone()),
                fields,
                ..change("calendarUpdated")
            }
        )
        .await
    );
    success_response(&doc, json!({ "calendar": ce::calendar_wire(&cal) }))
}

/// Whether `who` may see `cal` in a listing: the community's calendars to every member; a
/// group's where the group's visibility admits them, or they run it.
async fn calendar_visible(
    state: &AppState,
    who: &Viewer,
    cal: &Calendar,
) -> Result<bool, AppError> {
    if who.runs_calendar(cal) {
        return Ok(true);
    }
    if !who.active_member {
        return Ok(false);
    }
    let Some(g) = &cal.group_id else {
        return Ok(true);
    };
    let Some(group) = crate::groups::get(state.directory.ks(), g).await? else {
        return Ok(false);
    };
    let standing = crate::groups::Standing::read(state, &who.did).await?;
    Ok(standing.sees(&group))
}

async fn handle_calendar_list(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<cal_list::Payload>(&doc) {
        return r;
    }
    if !(who.active_member || who.runs_all()) {
        return denied(
            &doc,
            "calendars are read by this community's active members",
        );
    }
    if !events_on(state).await {
        return success_response(&doc, json!({ "items": [] }));
    }
    let p = &doc.payload;
    let group = str_of(p, "groupId");
    let archived = p
        .get("includeArchived")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    tri!(&doc, ce::community_calendar(&state.events_ks).await);
    let mut all = Vec::new();
    for cal in tri!(&doc, ce::calendars(&state.events_ks).await) {
        if group.is_some_and(|g| cal.group_id.as_deref() != Some(g)) {
            continue;
        }
        if cal.state == CalendarState::Archived && !archived {
            continue;
        }
        if tri!(&doc, calendar_visible(state, &who, &cal).await) {
            all.push(cal);
        }
    }
    all.sort_by(|a, b| {
        (!a.community, a.name.to_lowercase(), &a.calendar_id).cmp(&(
            !b.community,
            b.name.to_lowercase(),
            &b.calendar_id,
        ))
    });
    let binding = format!("calendars|{}|{group:?}|{archived}", who.did);
    let (items, next) = match page(state, &doc, &binding, &all, 200).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut body = json!({ "items": items.iter().map(ce::calendar_wire).collect::<Vec<_>>() });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

// ─── events ──────────────────────────────────────────────────────────────

async fn handle_create(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_create::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            CREATE_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let p = &doc.payload;
    let cal = match str_of(p, "calendarId") {
        Some(id) => match tri!(&doc, ce::get_calendar(&state.events_ks, id).await) {
            Some(c) if who.runs_calendar(&c) => c,
            _ => return not_found(&doc, "calendar"),
        },
        None => tri!(&doc, ce::community_calendar(&state.events_ks).await),
    };
    // VTI-EVT-013.
    if !who.runs_calendar(&cal) {
        return denied(
            &doc,
            "events in this calendar are created by those who run it",
        );
    }
    if cal.state == CalendarState::Archived {
        return declared(
            &doc,
            CREATE_ERR_CALENDAR_ARCHIVED,
            "This calendar is archived.",
        );
    }
    let when: When = match p.get("when").cloned().map(serde_json::from_value) {
        Some(Ok(w)) => w,
        _ => return malformed(&doc, "`when` is required"),
    };
    let audience = p
        .get("audience")
        .cloned()
        .unwrap_or_else(|| match &cal.group_id {
            Some(g) => json!({ "scope": "groups", "groups": [g] }),
            None => json!({ "scope": "members" }),
        });
    let registration = p
        .get("registration")
        .cloned()
        .unwrap_or_else(|| json!({ "mode": "open" }));
    let schema = tri!(&doc, schema(state).await);
    let checked = check_when(&when)
        .and(check_registration(&registration))
        .and(tri!(&doc, check_audience(state, &audience, &schema).await));
    if let Err(inv) = checked {
        return refuse_invalid(
            &doc,
            inv,
            CREATE_ERR_TIME_ZONE_UNKNOWN,
            CREATE_ERR_WHEN_INVALID,
            CREATE_ERR_AUDIENCE_INVALID,
            CREATE_ERR_REGISTRATION_INVALID,
        );
    }
    let entry = tri!(&doc, own_entry(state, &who).await);
    let now = Utc::now();
    let ev = EventRecord {
        event_id: ce::new_event_id(),
        calendar_id: cal.calendar_id.clone(),
        kind: str_of(p, "kind").unwrap_or("event").to_string(),
        status: Lifecycle::Draft,
        title: str_of(p, "title").unwrap_or_default().to_string(),
        description: str_of(p, "description").map(str::to_string),
        when,
        place_summary: str_of(p, "placeSummary").map(str::to_string),
        access: p.get("access").cloned(),
        audience,
        registration,
        roster: str_of(p, "roster")
            .and_then(Roster::parse)
            .or(cal.default_roster)
            .unwrap_or(Roster::Hidden),
        show_count: p.get("showCount").and_then(Value::as_bool).unwrap_or(false),
        count_threshold: p
            .get("countThreshold")
            .and_then(Value::as_u64)
            .map(|n| n as u32),
        listed: p.get("listed").and_then(Value::as_bool).unwrap_or(true),
        accessibility: p.get("accessibility").cloned(),
        suggested_reminder_minutes: reminders(p, "suggestedReminderMinutes")
            .unwrap_or_else(|| cal.default_reminder_minutes.clone()),
        sequence: 0,
        cancel_reason: None,
        published_at: None,
        cancelled_at: None,
        created_at: now,
        updated_at: now,
        created_by: entry,
    };
    // VTI-EVT-080, asked last.
    if let Some(why) = tri!(
        &doc,
        policy_refusal(state, &who, "create", &cal, &ev, "").await
    ) {
        return declared(&doc, CREATE_ERR_POLICY_REFUSED, why);
    }
    tri!(&doc, ce::put_event(&state.events_ks, &ev).await);
    // VTI-EVT-070: the creator is the first host. A member is appointed, so they keep hosting
    // whatever happens to their calendar authority; a creator who is no member (an
    // administrator) hosts through that authority alone, since an appointment granted by
    // someone who is not an active member goes straight to review (VTI-ACL-071).
    if who.active_member {
        tri!(
            &doc,
            hosts::appoint(state, &who.did, &who.did, &ev.event_id).await
        );
    }
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                calendar_id: Some(cal.calendar_id.clone()),
                ..event_change(&ev.event_id, "created")
            }
        )
        .await
    );
    let seen = Seen {
        ev,
        cal: Some(cal),
        host: true,
        own: None,
    };
    event_answer(state, &doc, &seen).await
}

/// The event a host acts on: `notFound` unless the caller hosts it.
async fn hosted(state: &AppState, who: &Viewer, doc: &Doc) -> Result<Seen, TrustTaskOutcome> {
    let id = str_of(&doc.payload, "eventId").unwrap_or_default();
    match visible_event(state, who, id).await {
        Ok(Some(s)) if s.host => Ok(s),
        Ok(Some(_)) => Err(denied(doc, "this is done by the event's hosts")),
        Ok(None) => Err(not_found(doc, "event")),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

async fn handle_update(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_update::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            UPDATE_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    let seen = match hosted(state, &who, &doc).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Seen { mut ev, cal, .. } = seen;
    if ev.status == Lifecycle::Cancelled {
        return declared(
            &doc,
            UPDATE_ERR_EVENT_CANCELLED,
            "A cancelled event does not change.",
        );
    }
    let p = doc.payload.clone();
    let published = ev.status == Lifecycle::Published;
    // VTI-EVT-051: fixed at publish; the same value is no change.
    if let Some(r) = str_of(&p, "roster").and_then(Roster::parse)
        && r != ev.roster
    {
        if published {
            return declared(
                &doc,
                UPDATE_ERR_ROSTER_LOCKED,
                "The roster setting was fixed when this event was published. Cancel it and \
                 create a new one to change it.",
            );
        }
        ev.roster = r;
    }
    let mut fields = Vec::new();
    let mut significant = false;
    if let Some(v) = p.get("when") {
        let Ok(w) = serde_json::from_value::<When>(v.clone()) else {
            return malformed(&doc, "`when` is malformed");
        };
        if w != ev.when {
            significant = true;
        }
        ev.when = w;
        fields.push("when".to_string());
    }
    if let Some(t) = str_of(&p, "title") {
        ev.title = t.to_string();
        fields.push("title".into());
    }
    for (key, slot) in [
        ("description", &mut ev.description),
        ("placeSummary", &mut ev.place_summary),
    ] {
        if let Some(v) = p.get(key) {
            *slot = v.as_str().map(str::to_string);
            fields.push(key.to_string());
        }
    }
    if let Some(v) = p.get("access") {
        let next = (!v.is_null()).then(|| v.clone());
        if next != ev.access {
            significant = true;
        }
        ev.access = next;
        fields.push("access".into());
    }
    if let Some(v) = p.get("accessibility") {
        ev.accessibility = (!v.is_null()).then(|| v.clone());
        fields.push("accessibility".into());
    }
    if let Some(v) = p.get("audience") {
        ev.audience = v.clone();
        fields.push("audience".into());
    }
    let capacity_before = ev.settings().capacity;
    if let Some(v) = p.get("registration") {
        ev.registration = v.clone();
        fields.push("registration".into());
    }
    if let Some(b) = p.get("showCount").and_then(Value::as_bool) {
        ev.show_count = b;
        fields.push("showCount".into());
    }
    if let Some(n) = p.get("countThreshold").and_then(Value::as_u64) {
        ev.count_threshold = Some(n as u32);
        fields.push("countThreshold".into());
    }
    if let Some(b) = p.get("listed").and_then(Value::as_bool) {
        ev.listed = b;
        fields.push("listed".into());
    }
    if let Some(r) = reminders(&p, "suggestedReminderMinutes") {
        ev.suggested_reminder_minutes = r;
        fields.push("suggestedReminderMinutes".into());
    }
    let schema = tri!(&doc, schema(state).await);
    let checked = check_when(&ev.when)
        .and(check_registration(&ev.registration))
        .and(tri!(
            &doc,
            check_audience(state, &ev.audience, &schema).await
        ));
    if let Err(inv) = checked {
        return refuse_invalid(
            &doc,
            inv,
            UPDATE_ERR_TIME_ZONE_UNKNOWN,
            UPDATE_ERR_WHEN_INVALID,
            UPDATE_ERR_AUDIENCE_INVALID,
            UPDATE_ERR_REGISTRATION_INVALID,
        );
    }
    let Some(cal) = cal else {
        return not_found(&doc, "event");
    };
    if let Some(why) = tri!(
        &doc,
        policy_refusal(state, &who, "update", &cal, &ev, &ev.event_id).await
    ) {
        return declared(&doc, UPDATE_ERR_POLICY_REFUSED, why);
    }
    // VTI-EVT-006.
    if published && significant {
        ev.sequence += 1;
    }
    ev.updated_at = Utc::now();
    tri!(&doc, ce::put_event(&state.events_ks, &ev).await);
    // A larger capacity moves the waitlist (VTI-EVT-033).
    if ev.settings().capacity != capacity_before {
        let regs = tri!(
            &doc,
            ce::registrations_of(&state.events_ks, &ev.event_id).await
        );
        for moved in ce::promote(&ev, &regs, ev.updated_at) {
            tri!(&doc, ce::put_registration(&state.events_ks, &moved).await);
            tri!(
                &doc,
                audit(state, &who.did, reg_change(&moved, "promoted")).await
            );
        }
    }
    drop(_guard);
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                fields,
                ..event_change(&ev.event_id, "updated")
            }
        )
        .await
    );
    let seen = Seen {
        ev,
        cal: Some(cal),
        host: true,
        own: None,
    };
    event_answer(state, &doc, &seen).await
}

async fn handle_publish(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_publish::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            PUBLISH_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    let Seen { mut ev, cal, .. } = match hosted(state, &who, &doc).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if ev.status != Lifecycle::Draft {
        return declared_with(
            &doc,
            PUBLISH_ERR_NOT_DRAFT,
            "Only a draft is published.",
            json!({ "status": ev.status.as_str() }),
        );
    }
    let Some(cal) = cal else {
        return not_found(&doc, "event");
    };
    if cal.state == CalendarState::Archived {
        return declared(
            &doc,
            PUBLISH_ERR_CALENDAR_ARCHIVED,
            "This event's calendar is archived.",
        );
    }
    let now = Utc::now();
    if ev.ended(now) {
        return declared(
            &doc,
            PUBLISH_ERR_EVENT_ENDED,
            "This event has already ended.",
        );
    }
    if let Some(why) = tri!(
        &doc,
        policy_refusal(state, &who, "publish", &cal, &ev, &ev.event_id).await
    ) {
        return declared(&doc, PUBLISH_ERR_POLICY_REFUSED, why);
    }
    ev.status = Lifecycle::Published;
    ev.published_at = Some(now);
    ev.updated_at = now;
    tri!(&doc, ce::put_event(&state.events_ks, &ev).await);
    drop(_guard);
    tri!(
        &doc,
        audit(state, &who.did, event_change(&ev.event_id, "published")).await
    );
    let seen = Seen {
        ev,
        cal: Some(cal),
        host: true,
        own: None,
    };
    event_answer(state, &doc, &seen).await
}

async fn handle_cancel(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_cancel::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            CANCEL_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    let Seen { mut ev, cal, .. } = match hosted(state, &who, &doc).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if ev.status != Lifecycle::Published {
        return declared_with(
            &doc,
            CANCEL_ERR_NOT_PUBLISHED,
            "Only a published event is cancelled; a draft is deleted.",
            json!({ "status": ev.status.as_str() }),
        );
    }
    let now = Utc::now();
    if ev.ended(now) {
        return declared(
            &doc,
            CANCEL_ERR_EVENT_ENDED,
            "This event has already ended.",
        );
    }
    ev.status = Lifecycle::Cancelled;
    ev.cancelled_at = Some(now);
    ev.cancel_reason = str_of(&doc.payload, "reason").map(str::to_string);
    ev.sequence += 1;
    ev.updated_at = now;
    tri!(&doc, ce::put_event(&state.events_ks, &ev).await);
    drop(_guard);
    tri!(
        &doc,
        audit(state, &who.did, event_change(&ev.event_id, "cancelled")).await
    );
    let seen = Seen {
        ev,
        cal,
        host: true,
        own: None,
    };
    event_answer(state, &doc, &seen).await
}

async fn handle_delete(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_delete::Payload>(&doc) {
        return r;
    }
    if !events_on(state).await {
        return declared(
            &doc,
            DELETE_ERR_EVENTS_OFF,
            "Events are turned off in this community.",
        );
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    let Seen { ev, .. } = match hosted(state, &who, &doc).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    // VTI-EVT-093.
    if ev.status != Lifecycle::Draft {
        return declared_with(
            &doc,
            DELETE_ERR_NOT_DRAFT,
            "Only a draft is deleted; a published event is cancelled.",
            json!({ "status": ev.status.as_str() }),
        );
    }
    tri!(&doc, ce::delete_event(&state.events_ks, &ev.event_id).await);
    drop(_guard);
    tri!(&doc, hosts::withdraw_all(state, &ev.event_id).await);
    tri!(
        &doc,
        audit(state, &who.did, event_change(&ev.event_id, "deleted")).await
    );
    success_response(&doc, json!({ "eventId": ev.event_id }))
}

async fn handle_show(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_show::Payload>(&doc) {
        return r;
    }
    let id = str_of(&doc.payload, "eventId").unwrap_or_default();
    let Some(seen) = tri!(&doc, visible_event(state, &who, id).await) else {
        return not_found(&doc, "event");
    };
    let regs = tri!(&doc, ce::registrations_of(&state.events_ks, id).await);
    let hosts = tri!(&doc, hosts::entries(state, id).await);
    let mut body = json!({ "event": ce::event_wire(&seen.ev, seen.host, &regs, &hosts) });
    if let Some(own) = &seen.own {
        body["myRegistration"] = ce::registration_wire(own, &regs);
    }
    success_response(&doc, body)
}

async fn handle_list(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_list::Payload>(&doc) {
        return r;
    }
    if !(who.active_member || who.runs_all()) {
        return denied(&doc, "events are read by this community's active members");
    }
    let p = &doc.payload;
    let at = |k: &str| {
        str_of(p, k)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&Utc))
    };
    let (from, to) = (at("from"), at("to"));
    if let (Some(f), Some(t)) = (from, to)
        && (t <= f || t - f > Duration::days(400))
    {
        return declared(
            &doc,
            LIST_ERR_RANGE_INVALID,
            "`to` comes after `from`, at most 400 days later.",
        );
    }
    if !events_on(state).await {
        return success_response(&doc, json!({ "items": [] }));
    }
    let calendar = str_of(p, "calendarId");
    let kind = str_of(p, "kind");
    let mine = p.get("mine").and_then(Value::as_bool).unwrap_or(false);
    let drafts = p
        .get("includeDrafts")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cancelled = p
        .get("includeCancelled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ks = &state.events_ks;
    let schema = tri!(&doc, schema(state).await);
    let cals: std::collections::HashMap<String, Calendar> = tri!(&doc, ce::calendars(ks).await)
        .into_iter()
        .map(|c| (c.calendar_id.clone(), c))
        .collect();
    let own: std::collections::HashMap<String, Registration> = match &who.entry_id {
        Some(e) => tri!(&doc, ce::registrations_by(ks, e).await)
            .into_iter()
            .map(|r| (r.event_id.clone(), r))
            .collect(),
        None => Default::default(),
    };
    let mut rows: Vec<(DateTime<Utc>, EventRecord, bool)> = Vec::new();
    for ev in tri!(&doc, ce::events(ks).await) {
        if calendar.is_some_and(|c| c != ev.calendar_id) || kind.is_some_and(|k| k != ev.kind) {
            continue;
        }
        let Ok((start, end)) = ev.interval() else {
            continue;
        };
        if from.is_some_and(|f| end <= f) || to.is_some_and(|t| start >= t) {
            continue;
        }
        let host = who.hosts(&ev, cals.get(&ev.calendar_id));
        let mine_reg = own.get(&ev.event_id);
        let live_mine = mine_reg.is_some_and(|r| r.status.is_live());
        if mine && !live_mine {
            continue;
        }
        let shown = match ev.status {
            Lifecycle::Draft => drafts && host,
            Lifecycle::Cancelled => {
                (cancelled || mine_reg.is_some())
                    && (host || mine_reg.is_some() || who.in_audience(&ev.audience, &schema))
            }
            Lifecycle::Published => {
                host || mine_reg.is_some() || (ev.listed && who.in_audience(&ev.audience, &schema))
            }
        };
        if shown {
            rows.push((start, ev, host));
        }
    }
    rows.sort_by(|a, b| (a.0, &a.1.event_id).cmp(&(b.0, &b.1.event_id)));
    let binding = format!(
        "list|{}|{from:?}|{to:?}|{calendar:?}|{kind:?}|{mine}|{drafts}|{cancelled}",
        who.did
    );
    let (rows, next) = match page(state, &doc, &binding, &rows, 200).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut items = Vec::with_capacity(rows.len());
    for (_, ev, host) in &rows {
        let regs = tri!(&doc, ce::registrations_of(ks, &ev.event_id).await);
        let hosts = tri!(&doc, hosts::entries(state, &ev.event_id).await);
        let mut item = json!({ "event": ce::event_wire(ev, *host, &regs, &hosts) });
        if let Some(r) = own.get(&ev.event_id) {
            item["myStatus"] = json!(r.status.as_str());
        }
        items.push(item);
    }
    let mut body = json!({ "items": items });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

async fn handle_mine(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<mine_list::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let since = str_of(p, "updatedSince")
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc));
    let statuses: Option<Vec<String>> = p.get("statuses").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    });
    let (Some(entry), true) = (&who.entry_id, events_on(state).await) else {
        return success_response(&doc, json!({ "items": [] }));
    };
    let ks = &state.events_ks;
    let mut rows = Vec::new();
    for reg in tri!(&doc, ce::registrations_by(ks, entry).await) {
        if statuses
            .as_ref()
            .is_some_and(|s| !s.iter().any(|x| x == reg.status.as_str()))
        {
            continue;
        }
        let Some(ev) = tri!(&doc, ce::get_event(ks, &reg.event_id).await) else {
            continue;
        };
        let changed = reg.updated_at.max(ev.updated_at);
        if since.is_some_and(|s| changed < s) {
            continue;
        }
        rows.push((changed, reg, ev));
    }
    rows.sort_by(|a, b| (a.0, &a.1.registration_id).cmp(&(b.0, &b.1.registration_id)));
    let binding = format!("mine|{}|{since:?}|{statuses:?}", who.did);
    let (rows, next) = match page(state, &doc, &binding, &rows, 100).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut items = Vec::with_capacity(rows.len());
    for (_, reg, ev) in &rows {
        let regs = tri!(&doc, ce::registrations_of(ks, &ev.event_id).await);
        items.push(json!({
            "registration": ce::registration_wire(reg, &regs),
            "event": ce::event_ref(ev),
        }));
    }
    let mut body = json!({ "items": items });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

async fn handle_access(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<access_show::Payload>(&doc) {
        return r;
    }
    let id = str_of(&doc.payload, "eventId").unwrap_or_default();
    let Some(seen) = tri!(&doc, visible_event(state, &who, id).await) else {
        return not_found(&doc, "event");
    };
    let access = seen.ev.access.clone().unwrap_or_else(|| json!({}));
    if !seen.host {
        if seen.ev.status == Lifecycle::Cancelled {
            return declared(
                &doc,
                ACCESS_ERR_EVENT_CANCELLED,
                "This event was cancelled.",
            );
        }
        // VTI-EVT-060.
        let status = seen.own.as_ref().map(|r| r.status);
        if status != Some(RegStatus::Going) {
            return declared_with(
                &doc,
                ACCESS_ERR_NOT_GOING,
                "Where it happens is released to registrants who are going.",
                json!({ "status": status.map_or("none", RegStatus::as_str) }),
            );
        }
        if let Some(at) = access
            .get("revealAt")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            && at.with_timezone(&Utc) > Utc::now()
        {
            return declared_with(
                &doc,
                ACCESS_ERR_NOT_YET,
                "Where it happens is released closer to the time.",
                json!({ "revealAt": stamp(at.with_timezone(&Utc)) }),
            );
        }
    }
    success_response(
        &doc,
        json!({ "eventId": seen.ev.event_id, "access": access, "sequence": seen.ev.sequence }),
    )
}

// ─── registrations ───────────────────────────────────────────────────────

/// The answers well formed against the event's questions (VTI-EVT-034).
fn answers_problem(questions: &[Value], answers: Option<&Value>) -> Option<String> {
    let empty = Map::new();
    let given = answers.and_then(Value::as_object).unwrap_or(&empty);
    for key in given.keys() {
        if !questions
            .iter()
            .any(|q| str_of(q, "questionId") == Some(key))
        {
            return Some(format!("{key} is not one of this event's questions"));
        }
    }
    for q in questions {
        let id = str_of(q, "questionId").unwrap_or_default();
        let required = q.get("required").and_then(Value::as_bool).unwrap_or(false);
        match given.get(id) {
            None if required => return Some(format!("{id} needs an answer")),
            None => {}
            Some(a) => {
                let ok = match str_of(q, "kind") {
                    Some("boolean") => a.is_boolean(),
                    Some("choice") => a.as_str().is_some_and(|s| {
                        q.get("choices")
                            .and_then(Value::as_array)
                            .is_some_and(|c| c.iter().any(|x| x.as_str() == Some(s)))
                    }),
                    _ => a.is_string(),
                };
                if !ok {
                    return Some(format!("{id}'s answer does not fit the question"));
                }
            }
        }
    }
    None
}

fn receipt(reg: &Registration, regs: &[Registration], ev: &EventRecord) -> Value {
    json!({ "registration": ce::registration_wire(reg, regs), "event": ce::event_ref(ev) })
}

async fn handle_register(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<reg_register::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let id = str_of(&p, "eventId").unwrap_or_default();
    let _guard = ce::WRITE_LOCK.lock().await;
    let Some(seen) = tri!(&doc, visible_event(state, &who, id).await) else {
        return not_found(&doc, "event");
    };
    let ev = &seen.ev;
    if ev.status == Lifecycle::Draft {
        return not_found(&doc, "event");
    }
    if ev.status == Lifecycle::Cancelled {
        return declared(
            &doc,
            REGISTER_ERR_EVENT_CANCELLED,
            "This event was cancelled.",
        );
    }
    // VTI-EVT-021: the audience, live — a registration held already lets them change it.
    let schema = tri!(&doc, schema(state).await);
    if seen.own.is_none() && !who.in_audience(&ev.audience, &schema) {
        return denied(&doc, "this event is for its audience");
    }
    let settings = ev.settings();
    if settings.mode == Mode::Closed {
        return declared(
            &doc,
            REGISTER_ERR_NOT_OPEN,
            "This event takes no registrations.",
        );
    }
    let now = Utc::now();
    // VTI-EVT-038.
    if settings.opens_at.is_some_and(|o| now < o) || ev.closes_at().is_some_and(|c| now >= c) {
        return declared(
            &doc,
            REGISTER_ERR_WINDOW_CLOSED,
            "Registrations are not open now.",
        );
    }
    if let Some(own) = &seen.own
        && matches!(own.status, RegStatus::Declined | RegStatus::Removed)
    {
        return declared_with(
            &doc,
            REGISTER_ERR_HOST_DECIDED,
            "A host decided this registration; it is not re-opened by the registrant.",
            json!({ "status": own.status.as_str() }),
        );
    }
    let wanted = match str_of(&p, "status") {
        Some("maybe") => RegStatus::Maybe,
        _ => RegStatus::Going,
    };
    if wanted == RegStatus::Maybe && settings.mode == Mode::Approval {
        return declared(
            &doc,
            REGISTER_ERR_MAYBE_NOT_ACCEPTED,
            "This event's hosts decide each registration; say going, or nothing.",
        );
    }
    let guests = p.get("guests").and_then(Value::as_u64).unwrap_or(0) as u32;
    if guests > settings.plus_ones {
        return declared_with(
            &doc,
            REGISTER_ERR_TOO_MANY_GUESTS,
            format!(
                "This event admits at most {} guests each.",
                settings.plus_ones
            ),
            json!({ "plusOnes": settings.plus_ones }),
        );
    }
    if let Some(problem) = answers_problem(&settings.questions, p.get("answers")) {
        return declared(&doc, REGISTER_ERR_ANSWERS_INVALID, problem);
    }
    // VTI-EVT-035.
    let acknowledged = str_of(&p, "codeOfConductAcknowledged").map(str::to_string);
    if let Some(sha) = &settings.code_of_conduct
        && acknowledged.as_deref() != Some(sha.as_str())
    {
        return declared_with(
            &doc,
            REGISTER_ERR_CODE_OF_CONDUCT_REQUIRED,
            "Read and acknowledge the code of conduct to register.",
            json!({ "sha256": sha }),
        );
    }
    let ks = &state.events_ks;
    let mut regs = tri!(&doc, ce::registrations_of(ks, id).await);
    let entry = tri!(&doc, own_entry(state, &who).await);
    let previous = regs.iter().position(|r| r.entry_id == entry);
    let others: Vec<Registration> = regs
        .iter()
        .filter(|r| r.entry_id != entry)
        .cloned()
        .collect();
    let prior = previous.map(|i| regs[i].clone());
    // Where it lands (VTI-EVT-031, 033).
    let status = match wanted {
        RegStatus::Maybe => RegStatus::Maybe,
        _ => match prior.as_ref().map(|r| r.status) {
            // A pending or waitlisted registrant keeps their place.
            Some(s @ (RegStatus::Pending | RegStatus::Waitlisted)) => s,
            _ if settings.mode == Mode::Approval
                && prior.as_ref().map(|r| r.status) != Some(RegStatus::Going) =>
            {
                RegStatus::Pending
            }
            _ if ce::fits(&settings, &others, 1 + guests) => RegStatus::Going,
            _ if settings.waitlist => RegStatus::Waitlisted,
            _ => {
                return declared(&doc, REGISTER_ERR_FULL, "This event is full.");
            }
        },
    };
    let reg = Registration {
        registration_id: prior
            .as_ref()
            .map_or_else(ce::new_registration_id, |r| r.registration_id.clone()),
        event_id: id.to_string(),
        entry_id: entry,
        status,
        guests,
        answers: p.get("answers").cloned(),
        code_of_conduct_acknowledged: acknowledged,
        waitlisted_at: match (status, prior.as_ref()) {
            (RegStatus::Waitlisted, Some(r)) if r.status == RegStatus::Waitlisted => {
                r.waitlisted_at
            }
            (RegStatus::Waitlisted, _) => Some(now),
            _ => None,
        },
        roster: ev.roster,
        event_sequence: ev.sequence,
        note: None,
        created_at: prior.as_ref().map_or(now, |r| r.created_at),
        updated_at: now,
    };
    tri!(&doc, ce::put_registration(ks, &reg).await);
    match previous {
        Some(i) => regs[i] = reg.clone(),
        None => regs.push(reg.clone()),
    }
    // Going to maybe, or fewer guests, frees places (VTI-EVT-033).
    for moved in ce::promote(ev, &regs, now) {
        tri!(&doc, ce::put_registration(ks, &moved).await);
        if let Some(r) = regs
            .iter_mut()
            .find(|r| r.registration_id == moved.registration_id)
        {
            *r = moved.clone();
        }
        tri!(
            &doc,
            audit(state, &who.did, reg_change(&moved, "promoted")).await
        );
    }
    drop(_guard);
    let what = if prior.is_some() {
        "registrationChanged"
    } else {
        "registered"
    };
    tri!(&doc, audit(state, &who.did, reg_change(&reg, what)).await);
    let mut body = receipt(&reg, &regs, ev);
    body["wasCreated"] = json!(prior.is_none());
    success_response(&doc, body)
}

async fn handle_withdraw(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<reg_withdraw::Payload>(&doc) {
        return r;
    }
    let id = str_of(&doc.payload, "eventId").unwrap_or_default();
    let _guard = ce::WRITE_LOCK.lock().await;
    let Some(seen) = tri!(&doc, visible_event(state, &who, id).await) else {
        return not_found(&doc, "event");
    };
    let Some(mut reg) = seen.own.clone() else {
        return declared(
            &doc,
            WITHDRAW_ERR_NOT_REGISTERED,
            "You hold no registration for this event.",
        );
    };
    let ks = &state.events_ks;
    // VTI-EVT-037: always allowed; a repeat, or a registration a host closed, changes nothing.
    let changed = reg.status.is_live();
    let now = Utc::now();
    if changed {
        reg.status = RegStatus::Withdrawn;
        reg.waitlisted_at = None;
        reg.event_sequence = seen.ev.sequence;
        reg.updated_at = now;
        tri!(&doc, ce::put_registration(ks, &reg).await);
    }
    let mut regs = tri!(&doc, ce::registrations_of(ks, id).await);
    if changed && seen.ev.status == Lifecycle::Published && !seen.ev.ended(now) {
        for moved in ce::promote(&seen.ev, &regs, now) {
            tri!(&doc, ce::put_registration(ks, &moved).await);
            tri!(
                &doc,
                audit(state, &who.did, reg_change(&moved, "promoted")).await
            );
        }
        regs = tri!(&doc, ce::registrations_of(ks, id).await);
    }
    drop(_guard);
    if changed {
        tri!(
            &doc,
            audit(state, &who.did, reg_change(&reg, "withdrawn")).await
        );
    }
    let mut body = receipt(&reg, &regs, &seen.ev);
    body["changed"] = json!(changed);
    success_response(&doc, body)
}

async fn handle_registrations(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<reg_list::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let id = str_of(p, "eventId").unwrap_or_default();
    let Some(seen) = tri!(&doc, visible_event(state, &who, id).await) else {
        return not_found(&doc, "event");
    };
    let regs = tri!(&doc, ce::registrations_of(&state.events_ks, id).await);
    let statuses: Option<Vec<String>> = p.get("statuses").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    });
    if seen.host {
        // VTI-EVT-073.
        let mut all: Vec<Registration> = regs
            .iter()
            .filter(|r| {
                statuses
                    .as_ref()
                    .is_none_or(|s| s.iter().any(|x| x == r.status.as_str()))
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| {
            (a.created_at, &a.registration_id).cmp(&(b.created_at, &b.registration_id))
        });
        let binding = format!("registrations|host|{}|{id}|{statuses:?}", who.did);
        let (page_items, next) = match page(state, &doc, &binding, &all, 100).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        let mut body = json!({
            "eventId": id,
            "view": "host",
            "registrations": page_items.iter().map(|r| ce::registration_wire(r, &regs)).collect::<Vec<_>>(),
        });
        if let Some(n) = next {
            body["nextCursor"] = json!(n);
        }
        return success_response(&doc, body);
    }
    // VTI-EVT-053: the roster view, on a visible roster, to a registrant going or maybe.
    if statuses.is_some() {
        return declared(
            &doc,
            REG_LIST_ERR_FILTER_NOT_PERMITTED,
            "The roster shows who is going or maybe; only hosts filter.",
        );
    }
    if seen.ev.roster == Roster::Hidden {
        return declared(
            &doc,
            REG_LIST_ERR_ROSTER_HIDDEN,
            "This event's roster is hidden.",
        );
    }
    if !seen
        .own
        .as_ref()
        .is_some_and(|r| matches!(r.status, RegStatus::Going | RegStatus::Maybe))
    {
        return declared(
            &doc,
            REG_LIST_ERR_NOT_REGISTERED,
            "The roster is shown to registrants who are going or maybe.",
        );
    }
    let mut all: Vec<Registration> = regs
        .iter()
        .filter(|r| matches!(r.status, RegStatus::Going | RegStatus::Maybe))
        .cloned()
        .collect();
    all.sort_by(|a, b| a.entry_id.cmp(&b.entry_id));
    let binding = format!("registrations|roster|{}|{id}", who.did);
    let (page_items, next) = match page(state, &doc, &binding, &all, 100).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut body = json!({
        "eventId": id,
        "view": "roster",
        "roster": page_items.iter().map(ce::roster_item).collect::<Vec<_>>(),
    });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    success_response(&doc, body)
}

/// The registration `registrationId` names, on an event the caller hosts.
async fn hosted_registration(
    state: &AppState,
    who: &Viewer,
    doc: &Doc,
) -> Result<(Registration, Seen), TrustTaskOutcome> {
    let rid = str_of(&doc.payload, "registrationId").unwrap_or_default();
    let reg = match ce::registration_by_id(&state.events_ks, rid).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(not_found(doc, "registration")),
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    match visible_event(state, who, &reg.event_id).await {
        Ok(Some(s)) if s.host => Ok((reg, s)),
        Ok(_) => Err(not_found(doc, "registration")),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

async fn handle_decide(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<reg_decide::Payload>(&doc) {
        return r;
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    let (mut reg, seen) = match hosted_registration(state, &who, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if seen.ev.status == Lifecycle::Cancelled {
        return declared(
            &doc,
            DECIDE_ERR_EVENT_CANCELLED,
            "This event was cancelled.",
        );
    }
    if reg.status != RegStatus::Pending {
        return declared_with(
            &doc,
            DECIDE_ERR_NOT_PENDING,
            "Only a pending registration is decided.",
            json!({ "status": reg.status.as_str() }),
        );
    }
    let decision = str_of(&doc.payload, "decision")
        .unwrap_or("decline")
        .to_string();
    let ks = &state.events_ks;
    let regs = tri!(&doc, ce::registrations_of(ks, &reg.event_id).await);
    let now = Utc::now();
    let settings = seen.ev.settings();
    reg.status = if decision == "approve" {
        let others: Vec<Registration> = regs
            .iter()
            .filter(|r| r.registration_id != reg.registration_id)
            .cloned()
            .collect();
        if ce::fits(&settings, &others, 1 + reg.guests) {
            RegStatus::Going
        } else if settings.waitlist {
            reg.waitlisted_at = Some(now);
            RegStatus::Waitlisted
        } else {
            return declared(
                &doc,
                DECIDE_ERR_FULL,
                "This event is full; the registration stays pending.",
            );
        }
    } else {
        RegStatus::Declined
    };
    reg.note = str_of(&doc.payload, "note").map(str::to_string);
    reg.event_sequence = seen.ev.sequence;
    reg.updated_at = now;
    tri!(&doc, ce::put_registration(ks, &reg).await);
    let regs = tri!(&doc, ce::registrations_of(ks, &reg.event_id).await);
    drop(_guard);
    let what = if decision == "approve" {
        "approved"
    } else {
        "declined"
    };
    tri!(&doc, audit(state, &who.did, reg_change(&reg, what)).await);
    let mut body = receipt(&reg, &regs, &seen.ev);
    body["decision"] = json!(decision);
    success_response(&doc, body)
}

async fn handle_remove(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<reg_remove::Payload>(&doc) {
        return r;
    }
    let _guard = ce::WRITE_LOCK.lock().await;
    let (mut reg, seen) = match hosted_registration(state, &who, &doc).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let now = Utc::now();
    if seen.ev.ended(now) {
        return declared(
            &doc,
            REMOVE_ERR_EVENT_ENDED,
            "This event has ended; its registrations stand.",
        );
    }
    let ks = &state.events_ks;
    let changed = reg.status.is_live();
    if changed {
        reg.status = RegStatus::Removed;
        reg.waitlisted_at = None;
        reg.note = str_of(&doc.payload, "note").map(str::to_string);
        reg.event_sequence = seen.ev.sequence;
        reg.updated_at = now;
        tri!(&doc, ce::put_registration(ks, &reg).await);
        let regs = tri!(&doc, ce::registrations_of(ks, &reg.event_id).await);
        if seen.ev.status == Lifecycle::Published {
            for moved in ce::promote(&seen.ev, &regs, now) {
                tri!(&doc, ce::put_registration(ks, &moved).await);
                tri!(
                    &doc,
                    audit(state, &who.did, reg_change(&moved, "promoted")).await
                );
            }
        }
    }
    let regs = tri!(&doc, ce::registrations_of(ks, &reg.event_id).await);
    drop(_guard);
    if changed {
        tri!(
            &doc,
            audit(state, &who.did, reg_change(&reg, "removed")).await
        );
    }
    let mut body = receipt(&reg, &regs, &seen.ev);
    body["changed"] = json!(changed);
    success_response(&doc, body)
}

// ─── hosts ───────────────────────────────────────────────────────────────

async fn host_list_answer(state: &AppState, doc: &Doc, event_id: &str) -> TrustTaskOutcome {
    match hosts::entries(state, event_id).await {
        Ok(h) => success_response(doc, json!({ "eventId": event_id, "hosts": h })),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

async fn handle_hosts_appoint(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<hosts_appoint::Payload>(&doc) {
        return r;
    }
    let seen = match hosted(state, &who, &doc).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if seen.ev.status == Lifecycle::Cancelled {
        return declared(
            &doc,
            APPOINT_ERR_EVENT_CANCELLED,
            "This event was cancelled.",
        );
    }
    let entry = str_of(&doc.payload, "entryId").unwrap_or_default();
    // VTI-EVT-071: an active member.
    let subject = tri!(
        &doc,
        crate::directory::read::subject_by_entry(state, entry).await
    );
    let Some(subject) = subject.filter(|s| s.active) else {
        return declared(&doc, APPOINT_ERR_NOT_ELIGIBLE, "Hosts are active members.");
    };
    if tri!(&doc, hosts::entries(state, &seen.ev.event_id).await)
        .iter()
        .any(|e| e == entry)
    {
        return declared(
            &doc,
            APPOINT_ERR_ALREADY_HOST,
            "This member already hosts the event.",
        );
    }
    tri!(
        &doc,
        hosts::appoint(state, &who.did, &subject.card.did, &seen.ev.event_id).await
    );
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                entry_id: Some(entry.to_string()),
                ..event_change(&seen.ev.event_id, "hostAppointed")
            }
        )
        .await
    );
    host_list_answer(state, &doc, &seen.ev.event_id).await
}

async fn handle_hosts_remove(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match host_signer(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<hosts_remove::Payload>(&doc) {
        return r;
    }
    let seen = match hosted(state, &who, &doc).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let entry = str_of(&doc.payload, "entryId").unwrap_or_default();
    let current = tri!(&doc, hosts::entries(state, &seen.ev.event_id).await);
    if !current.iter().any(|e| e == entry) {
        return declared(
            &doc,
            HOSTS_REMOVE_ERR_NOT_HOST,
            "This member does not host the event.",
        );
    }
    // VTI-EVT-072.
    if current.len() == 1 && seen.ev.status == Lifecycle::Published {
        return declared(
            &doc,
            HOSTS_REMOVE_ERR_LAST_HOST,
            "A published event keeps at least one host; appoint another first.",
        );
    }
    // The host's DID from their card: a host need not be a member (an administrator who
    // created the event hosts it), so never through the member-only subject lookup.
    let card = tri!(
        &doc,
        crate::directory::cards::get(state.directory.ks(), entry).await
    );
    if let Some(c) = card {
        tri!(
            &doc,
            hosts::withdraw(state, &c.did, &seen.ev.event_id).await
        );
    }
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                entry_id: Some(entry.to_string()),
                ..event_change(&seen.ev.event_id, "hostRemoved")
            }
        )
        .await
    );
    host_list_answer(state, &doc, &seen.ev.event_id).await
}

async fn handle_hosts_list(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<hosts_list::Payload>(&doc) {
        return r;
    }
    let id = str_of(&doc.payload, "eventId").unwrap_or_default();
    if tri!(&doc, visible_event(state, &who, id).await).is_none() {
        return not_found(&doc, "event");
    }
    host_list_answer(state, &doc, id).await
}

// ─── reports ─────────────────────────────────────────────────────────────

async fn handle_report(state: &AppState, ctx: &JoinAuthCtx, doc: Doc) -> TrustTaskOutcome {
    let who = match member(state, ctx, &doc).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = parse_spec_payload::<ev_report::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let id = str_of(p, "eventId").unwrap_or_default();
    let Some(seen) = tri!(&doc, visible_event(state, &who, id).await) else {
        return not_found(&doc, "event");
    };
    if !who.active_member {
        return denied(
            &doc,
            "events are reported by this community's active members",
        );
    }
    let entry = tri!(&doc, own_entry(state, &who).await);
    let ks = &state.events_ks;
    let _guard = ce::WRITE_LOCK.lock().await;
    if let Some(open) = tri!(&doc, ce::open_report(ks, id, &entry).await) {
        return declared_with(
            &doc,
            REPORT_ERR_ALREADY_REPORTED,
            "You have already reported this event.",
            json!({ "reportId": open.report_id }),
        );
    }
    let now = Utc::now();
    let limit = state.config.read().await.events.reports_per_day;
    let today = tri!(&doc, ce::reports(ks).await)
        .iter()
        .filter(|r| r.entry_id == entry && now - r.created_at < Duration::days(1))
        .count();
    if today >= limit as usize {
        return declared(
            &doc,
            REPORT_ERR_LIMIT_REACHED,
            format!("You have made this community's limit of {limit} reports today."),
        );
    }
    let report = Report {
        report_id: ce::new_report_id(),
        event_id: seen.ev.event_id.clone(),
        entry_id: entry.clone(),
        reason: str_of(p, "reason").unwrap_or("other").to_string(),
        note: str_of(p, "note").map(str::to_string),
        created_at: now,
        closed: false,
    };
    tri!(&doc, ce::put_report(ks, &report).await);
    drop(_guard);
    // VTI-EVT-081: on the administrators' action list, one item per event. A failure here is
    // made good by the events sweeper; the report itself is kept.
    if let Err(e) =
        crate::admin_actions::queues::raise_event_report(state, &report, &seen.ev.title).await
    {
        tracing::warn!(error = %e, "an event report could not be raised on the action list; the sweeper will");
    }
    tri!(
        &doc,
        audit(
            state,
            &who.did,
            EventChangedData {
                entry_id: Some(entry),
                fields: vec![report.reason.clone()],
                ..event_change(&report.event_id, "reported")
            }
        )
        .await
    );
    success_response(&doc, json!({ "reportId": report.report_id }))
}
