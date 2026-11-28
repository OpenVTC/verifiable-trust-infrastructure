//! Community events over the signed-document door (`vtc/events/*`, VTI-EVT-001 – 095).
//!
//! Every declared refusal is driven here and asserted by its code (the error-code census
//! names these tests), beside the paths that succeed: calendars, the event lifecycle, the
//! audience, registration with capacity and the waitlist, the roster, access details, hosts
//! by appointment, reports and the member's own registrations.

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vtc_service::acl::{
    AdminAuthority, AdminRole, Capability, CapabilityGrant, CapabilityScope, ResourceQualifier,
    VtcRole, store_acl_entry,
};
use vtc_service::test_support::TestVtc;
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{admin, call, party_with_role, payload};

use vti_specs::vtc::events as e;

const CAL_CREATE_ERR_EVENTS_OFF: &str = e::calendars::create::v0_1::error_codes::EVENTS_OFF.code;
const CAL_CREATE_ERR_GROUP_NOT_FOUND: &str =
    e::calendars::create::v0_1::error_codes::GROUP_NOT_FOUND.code;
const CAL_CREATE_ERR_GROUP_HAS_CALENDAR: &str =
    e::calendars::create::v0_1::error_codes::GROUP_HAS_CALENDAR.code;
const CAL_CREATE_ERR_SETTINGS_INVALID: &str =
    e::calendars::create::v0_1::error_codes::SETTINGS_INVALID.code;
const CAL_UPDATE_ERR_EVENTS_OFF: &str = e::calendars::update::v0_1::error_codes::EVENTS_OFF.code;
const CAL_UPDATE_ERR_COMMUNITY_CALENDAR: &str =
    e::calendars::update::v0_1::error_codes::COMMUNITY_CALENDAR.code;
const CAL_UPDATE_ERR_GROUP_HAS_CALENDAR: &str =
    e::calendars::update::v0_1::error_codes::GROUP_HAS_CALENDAR.code;
const CAL_UPDATE_ERR_SETTINGS_INVALID: &str =
    e::calendars::update::v0_1::error_codes::SETTINGS_INVALID.code;
const CREATE_ERR_EVENTS_OFF: &str = e::create::v0_2::error_codes::EVENTS_OFF.code;
const CREATE_ERR_CALENDAR_ARCHIVED: &str = e::create::v0_2::error_codes::CALENDAR_ARCHIVED.code;
const CREATE_ERR_TIME_ZONE_UNKNOWN: &str = e::create::v0_2::error_codes::TIME_ZONE_UNKNOWN.code;
const CREATE_ERR_WHEN_INVALID: &str = e::create::v0_2::error_codes::WHEN_INVALID.code;
const CREATE_ERR_AUDIENCE_INVALID: &str = e::create::v0_2::error_codes::AUDIENCE_INVALID.code;
const CREATE_ERR_REGISTRATION_INVALID: &str =
    e::create::v0_2::error_codes::REGISTRATION_INVALID.code;
const CREATE_ERR_POLICY_REFUSED: &str = e::create::v0_2::error_codes::POLICY_REFUSED.code;
const UPDATE_ERR_EVENTS_OFF: &str = e::update::v0_2::error_codes::EVENTS_OFF.code;
const UPDATE_ERR_EVENT_CANCELLED: &str = e::update::v0_2::error_codes::EVENT_CANCELLED.code;
const UPDATE_ERR_ROSTER_LOCKED: &str = e::update::v0_2::error_codes::ROSTER_LOCKED.code;
const UPDATE_ERR_TIME_ZONE_UNKNOWN: &str = e::update::v0_2::error_codes::TIME_ZONE_UNKNOWN.code;
const UPDATE_ERR_WHEN_INVALID: &str = e::update::v0_2::error_codes::WHEN_INVALID.code;
const UPDATE_ERR_AUDIENCE_INVALID: &str = e::update::v0_2::error_codes::AUDIENCE_INVALID.code;
const UPDATE_ERR_REGISTRATION_INVALID: &str =
    e::update::v0_2::error_codes::REGISTRATION_INVALID.code;
const UPDATE_ERR_POLICY_REFUSED: &str = e::update::v0_2::error_codes::POLICY_REFUSED.code;
const PUBLISH_ERR_EVENTS_OFF: &str = e::publish::v0_1::error_codes::EVENTS_OFF.code;
const PUBLISH_ERR_NOT_DRAFT: &str = e::publish::v0_1::error_codes::NOT_DRAFT.code;
const PUBLISH_ERR_CALENDAR_ARCHIVED: &str = e::publish::v0_1::error_codes::CALENDAR_ARCHIVED.code;
const PUBLISH_ERR_EVENT_ENDED: &str = e::publish::v0_1::error_codes::EVENT_ENDED.code;
const PUBLISH_ERR_POLICY_REFUSED: &str = e::publish::v0_1::error_codes::POLICY_REFUSED.code;
const CANCEL_ERR_EVENTS_OFF: &str = e::cancel::v0_1::error_codes::EVENTS_OFF.code;
const CANCEL_ERR_NOT_PUBLISHED: &str = e::cancel::v0_1::error_codes::NOT_PUBLISHED.code;
const CANCEL_ERR_EVENT_ENDED: &str = e::cancel::v0_1::error_codes::EVENT_ENDED.code;
const DELETE_ERR_EVENTS_OFF: &str = e::delete::v0_1::error_codes::EVENTS_OFF.code;
const DELETE_ERR_NOT_DRAFT: &str = e::delete::v0_1::error_codes::NOT_DRAFT.code;
const LIST_ERR_RANGE_INVALID: &str = e::list::v0_2::error_codes::RANGE_INVALID.code;
const ACCESS_ERR_NOT_GOING: &str = e::access::show::v0_1::error_codes::NOT_GOING.code;
const ACCESS_ERR_NOT_YET: &str = e::access::show::v0_1::error_codes::NOT_YET.code;
const ACCESS_ERR_EVENT_CANCELLED: &str = e::access::show::v0_1::error_codes::EVENT_CANCELLED.code;
const REGISTER_ERR_NOT_OPEN: &str = e::registrations::register::v0_2::error_codes::NOT_OPEN.code;
const REGISTER_ERR_EVENT_CANCELLED: &str =
    e::registrations::register::v0_2::error_codes::EVENT_CANCELLED.code;
const REGISTER_ERR_WINDOW_CLOSED: &str =
    e::registrations::register::v0_2::error_codes::WINDOW_CLOSED.code;
const REGISTER_ERR_FULL: &str = e::registrations::register::v0_2::error_codes::FULL.code;
const REGISTER_ERR_TOO_MANY_GUESTS: &str =
    e::registrations::register::v0_2::error_codes::TOO_MANY_GUESTS.code;
const REGISTER_ERR_ANSWERS_INVALID: &str =
    e::registrations::register::v0_2::error_codes::ANSWERS_INVALID.code;
const REGISTER_ERR_CODE_OF_CONDUCT_REQUIRED: &str =
    e::registrations::register::v0_2::error_codes::CODE_OF_CONDUCT_REQUIRED.code;
const REGISTER_ERR_MAYBE_NOT_ACCEPTED: &str =
    e::registrations::register::v0_2::error_codes::MAYBE_NOT_ACCEPTED.code;
const REGISTER_ERR_HOST_DECIDED: &str =
    e::registrations::register::v0_2::error_codes::HOST_DECIDED.code;
const WITHDRAW_ERR_NOT_REGISTERED: &str =
    e::registrations::withdraw::v0_2::error_codes::NOT_REGISTERED.code;
const REG_LIST_ERR_ROSTER_HIDDEN: &str =
    e::registrations::list::v0_2::error_codes::ROSTER_HIDDEN.code;
const REG_LIST_ERR_NOT_REGISTERED: &str =
    e::registrations::list::v0_2::error_codes::NOT_REGISTERED.code;
const REG_LIST_ERR_FILTER_NOT_PERMITTED: &str =
    e::registrations::list::v0_2::error_codes::FILTER_NOT_PERMITTED.code;
const DECIDE_ERR_NOT_PENDING: &str = e::registrations::decide::v0_2::error_codes::NOT_PENDING.code;
const DECIDE_ERR_FULL: &str = e::registrations::decide::v0_2::error_codes::FULL.code;
const DECIDE_ERR_EVENT_CANCELLED: &str =
    e::registrations::decide::v0_2::error_codes::EVENT_CANCELLED.code;
const REMOVE_ERR_EVENT_ENDED: &str = e::registrations::remove::v0_2::error_codes::EVENT_ENDED.code;
const APPOINT_ERR_NOT_ELIGIBLE: &str = e::hosts::appoint::v0_1::error_codes::NOT_ELIGIBLE.code;
const APPOINT_ERR_ALREADY_HOST: &str = e::hosts::appoint::v0_1::error_codes::ALREADY_HOST.code;
const APPOINT_ERR_EVENT_CANCELLED: &str =
    e::hosts::appoint::v0_1::error_codes::EVENT_CANCELLED.code;
const HOSTS_REMOVE_ERR_NOT_HOST: &str = e::hosts::remove::v0_1::error_codes::NOT_HOST.code;
const HOSTS_REMOVE_ERR_LAST_HOST: &str = e::hosts::remove::v0_1::error_codes::LAST_HOST.code;
const REPORT_ERR_ALREADY_REPORTED: &str = e::report::v0_1::error_codes::ALREADY_REPORTED.code;
const REPORT_ERR_LIMIT_REACHED: &str = e::report::v0_1::error_codes::LIMIT_REACHED.code;

const SPEC: &str = "https://trusttasks.org/spec/";
const UNKNOWN_EVENT: &str = "evt_AAAAAAAAAAAAAAAAAAAAAA";
const UNKNOWN_GROUP: &str = "grp_AAAAAAAAAAAAAAAAAAAAAA";
const GROUP: &str = "grp_EngineeringGroup0001";
const COC_SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// The served version of each task: 0.2 where phase 2 moved it, 0.1 otherwise.
fn uri(task: &str) -> String {
    const AT_0_2: &[&str] = &[
        "create",
        "update",
        "show",
        "list",
        "mine/list",
        "registrations/register",
        "registrations/withdraw",
        "registrations/list",
        "registrations/decide",
        "registrations/remove",
    ];
    let v = if AT_0_2.contains(&task) { "0.2" } else { "0.1" };
    format!("{SPEC}vtc/events/{task}/{v}")
}

fn tt_error_code(doc: &Value) -> &str {
    doc.pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// A thing the caller may not see is answered as one that does not exist (VTI-EVT-023):
/// `taskFailed` with the reason `not_found`, as every VTC family answers it.
fn assert_not_found(doc: &Value) {
    assert_eq!(tt_error_code(doc), "taskFailed", "{doc}");
    assert_eq!(doc["payload"]["details"]["reason"], "not_found", "{doc}");
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─── fixtures ────────────────────────────────────────────────────────────

async fn community() -> TestVtc {
    let tv = TestVtc::builder()
        .with_signers(true)
        .with_audit(true)
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &tv.state.policies_ks,
        &tv.state.active_policies_ks,
    )
    .await
    .unwrap();
    tv
}

/// An active member with a directory card.
async fn member(tv: &TestVtc) -> Party {
    let m = party_with_role(tv, VtcRole::Member, &[]).await;
    vtc_service::members::store_member(
        &tv.state.members_ks,
        &vtc_service::members::Member::fresh(m.did.clone()),
    )
    .await
    .unwrap();
    entry_of(tv, &m).await;
    m
}

async fn entry_of(tv: &TestVtc, who: &Party) -> String {
    vtc_service::directory::cards::ensure(
        tv.state.directory.ks(),
        &who.did,
        &vtc_service::directory::model::Settings::default(),
        None,
    )
    .await
    .unwrap()
    .entry_id
}

/// An active member holding `vtc.events.manage` at `at` (unqualified when `None`), and
/// nothing else administrative.
async fn runner(tv: &TestVtc, at: Option<ResourceQualifier>) -> Party {
    let p = member(tv).await;
    let mut entry = vtc_service::acl::get_acl_entry(&tv.state.acl_ks, &p.did)
        .await
        .unwrap()
        .unwrap();
    entry.admin = AdminAuthority {
        capabilities: CapabilityScope::listed(vec![CapabilityGrant {
            capability: Capability::EventsManage,
            resource: at,
            additive: false,
        }])
        .unwrap(),
        ..AdminAuthority::for_role(AdminRole::CommunityAdmin)
    };
    store_acl_entry(&tv.state.acl_ks, &entry).await.unwrap();
    p
}

/// A static group `GROUP` with `who` as its member.
async fn group_with(tv: &TestVtc, who: &[&Party]) {
    let ks = tv.state.directory.ks();
    let now = Utc::now();
    let g: vtc_service::groups::Group = serde_json::from_value(json!({
        "groupId": GROUP,
        "groupDid": Party::new().did,
        "signingKeyId": "k",
        "name": "Engineering",
        "joinPolicy": "closed",
        "visibility": "members",
        "showMembers": "members",
        "issuesCredentials": false,
        "createdAt": now,
        "updatedAt": now,
    }))
    .unwrap();
    vtc_service::groups::put(ks, &g).await.unwrap();
    for p in who {
        let entry = entry_of(tv, p).await;
        vtc_service::groups::put_membership(
            ks,
            &vtc_service::groups::Membership {
                group_id: GROUP.into(),
                entry_id: entry,
                source: "added".into(),
                since: now,
                state: "active".into(),
                credential_id: None,
                credential_valid_until: None,
            },
        )
        .await
        .unwrap();
    }
}

async fn activate_events_policy(tv: &TestVtc, source: &str) {
    use sha2::{Digest, Sha256};
    use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    let id = uuid::Uuid::new_v4();
    let now = Utc::now();
    store_policy(
        &tv.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::Events,
            rego_source: source.into(),
            sha256: Sha256::digest(source.as_bytes()).into(),
            activated_at: Some(now),
            author_did: "did:key:policy-author".into(),
            created_at: now,
            version: 99,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(&tv.state.active_policies_ks, PolicyPurpose::Events, id)
        .await
        .unwrap();
}

const DENY_PUBLISH: &str = r#"package vtc.events
import rego.v1
default decision := {"effect": "allow"}
decision := {"effect": "deny", "with": {"code": "no", "reason": "not this week"}} if {
    input.event.kind == "meeting"
}
"#;

/// A `when` starting `days` from now, an hour long, in UTC.
fn when_in(days: i64) -> Value {
    let start = (Utc::now() + Duration::days(days)).format("%Y-%m-%dT%H:%M:%S");
    json!({ "start": start.to_string(), "timeZone": "Etc/UTC", "duration": "PT1H" })
}

fn body(title: &str) -> Value {
    json!({ "title": title, "when": when_in(7) })
}

async fn create(tv: &TestVtc, who: &Party, body: Value) -> String {
    let (status, doc) = call(tv, who, &uri("create"), body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["event"]["eventId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn publish(tv: &TestVtc, who: &Party, id: &str) {
    let (status, doc) = call(tv, who, &uri("publish"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

/// A published event, made by `who`.
async fn published(tv: &TestVtc, who: &Party, body: Value) -> String {
    let id = create(tv, who, body).await;
    publish(tv, who, &id).await;
    id
}

async fn register(tv: &TestVtc, who: &Party, id: &str, extra: Value) -> (StatusCode, Value) {
    let mut p = json!({ "eventId": id, "status": "going" });
    if let Value::Object(m) = extra {
        for (k, v) in m {
            p[k] = v;
        }
    }
    call(tv, who, &uri("registrations/register"), p).await
}

async fn status_of(tv: &TestVtc, who: &Party, id: &str) -> String {
    let (_, doc) = call(tv, who, &uri("show"), json!({ "eventId": id })).await;
    payload(&doc)["myRegistration"]["status"]
        .as_str()
        .unwrap_or("none")
        .to_string()
}

/// Move a stored event into the past, as time passing would.
async fn move_to_past(tv: &TestVtc, id: &str) {
    let ks = &tv.state.events_ks;
    let mut ev = vtc_service::community_events::get_event(ks, id)
        .await
        .unwrap()
        .unwrap();
    ev.when = serde_json::from_value(when_in(-2)).unwrap();
    vtc_service::community_events::put_event(ks, &ev)
        .await
        .unwrap();
}

async fn audit_changes(tv: &TestVtc) -> Vec<String> {
    tv.state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vtc_audit::AuditEnvelope>(&v).ok())
        .filter_map(|env| match env.event {
            vtc_audit::AuditEvent::EventChanged(d) => Some(d.change),
            _ => None,
        })
        .collect()
}

// ─── calendars ───────────────────────────────────────────────────────────

/// VTI-EVT-010 – 014: calendars, the community's own first and never archived; a group's run
/// by those who run its events; one active per group.
#[tokio::test]
async fn vti_evt_013_calendars_are_run_by_their_authority() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    group_with(&tv, &[&alice]).await;

    // A member without the capability makes none.
    let (status, _) = call(
        &tv,
        &alice,
        &uri("calendars/create"),
        json!({ "name": "Mine" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "Nowhere", "groupId": UNKNOWN_GROUP }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CAL_CREATE_ERR_GROUP_NOT_FOUND, "{doc}");

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "   " }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CAL_CREATE_ERR_SETTINGS_INVALID,
        "{doc}"
    );

    // The group's events are run by a holder of vtc.events.manage at the group.
    let lead = runner(&tv, Some(ResourceQualifier::Group(GROUP.into()))).await;
    let (status, doc) = call(
        &tv,
        &lead,
        &uri("calendars/create"),
        json!({ "name": "Engineering", "groupId": GROUP, "defaultRoster": "visible", "defaultReminderMinutes": [1440] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let group_cal = payload(&doc)["calendar"]["calendarId"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "Engineering 2", "groupId": GROUP }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CAL_CREATE_ERR_GROUP_HAS_CALENDAR,
        "{doc}"
    );

    // The list: the community's own first, the group's to a member of it.
    let (status, doc) = call(&tv, &alice, &uri("calendars/list"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let items = payload(&doc)["items"].as_array().unwrap().clone();
    assert_eq!(items[0]["community"], true, "{doc}");
    assert!(items.iter().any(|c| c["calendarId"] == group_cal.as_str()));
    let community_cal = items[0]["calendarId"].as_str().unwrap().to_string();

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/update"),
        json!({ "calendarId": community_cal, "state": "archived" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CAL_UPDATE_ERR_COMMUNITY_CALENDAR,
        "{doc}"
    );
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/update"),
        json!({ "calendarId": group_cal, "name": " " }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CAL_UPDATE_ERR_SETTINGS_INVALID,
        "{doc}"
    );

    // Archive the group's, make another, then the first cannot come back.
    let (status, doc) = call(
        &tv,
        &lead,
        &uri("calendars/update"),
        json!({ "calendarId": group_cal, "state": "archived" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, doc) = call(
        &tv,
        &lead,
        &uri("calendars/create"),
        json!({ "name": "Engineering again", "groupId": GROUP }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(
        &tv,
        &lead,
        &uri("calendars/update"),
        json!({ "calendarId": group_cal, "state": "active" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CAL_UPDATE_ERR_GROUP_HAS_CALENDAR,
        "{doc}"
    );
    assert!(
        audit_changes(&tv)
            .await
            .contains(&"calendarCreated".to_string())
    );
}

/// VTI-EVT-007: with events off, every change is refused `eventsOff` and reads answer nothing.
#[tokio::test]
async fn vti_evt_007_events_off_refuses_every_change() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let draft = create(&tv, &chair, body("Draft")).await;
    let live = published(&tv, &chair, body("Live")).await;
    let (_, doc) = call(&tv, &chair, &uri("calendars/list"), json!({})).await;
    let cal = payload(&doc)["items"][0]["calendarId"]
        .as_str()
        .unwrap()
        .to_string();
    tv.state.config.write().await.events.enabled = false;

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "X" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CAL_CREATE_ERR_EVENTS_OFF, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/update"),
        json!({ "calendarId": cal, "name": "Y" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CAL_UPDATE_ERR_EVENTS_OFF, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("create"), body("Off")).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_EVENTS_OFF, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": live, "title": "Z" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_EVENTS_OFF, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("publish"), json!({ "eventId": draft })).await;
    assert_eq!(tt_error_code(&doc), PUBLISH_ERR_EVENTS_OFF, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("cancel"), json!({ "eventId": live })).await;
    assert_eq!(tt_error_code(&doc), CANCEL_ERR_EVENTS_OFF, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("delete"), json!({ "eventId": draft })).await;
    assert_eq!(tt_error_code(&doc), DELETE_ERR_EVENTS_OFF, "{doc}");
    let (status, doc) = call(&tv, &chair, &uri("list"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["items"], json!([]));
    let (_, doc) = call(&tv, &chair, &uri("show"), json!({ "eventId": live })).await;
    assert_not_found(&doc);
}

// ─── events ──────────────────────────────────────────────────────────────

/// VTI-EVT-005, 020, 031 – 036: an event's time, audience and registration settings are
/// checked on create and on update.
#[tokio::test]
async fn vti_evt_005_create_and_update_check_the_event() {
    let tv = community().await;
    let chair = admin(&tv).await;

    let bad_zone = json!({ "title": "x", "when": { "start": "2030-01-01T10:00:00", "timeZone": "Mars/Olympus", "duration": "PT1H" } });
    let bad_when = json!({ "title": "x", "when": { "start": "2030-01-01T10:00:00", "timeZone": "Etc/UTC", "duration": "PT5H", "showWithoutTime": true } });
    let bad_audience = json!({ "title": "x", "when": when_in(3), "audience": { "scope": "groups", "groups": [UNKNOWN_GROUP] } });
    let bad_registration = json!({ "title": "x", "when": when_in(3), "registration": { "mode": "open", "waitlist": true } });

    let (_, doc) = call(&tv, &chair, &uri("create"), bad_zone).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_TIME_ZONE_UNKNOWN, "{doc}");
    assert_eq!(doc["payload"]["details"]["timeZone"], "Mars/Olympus");
    let (_, doc) = call(&tv, &chair, &uri("create"), bad_when).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_WHEN_INVALID, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("create"), bad_audience).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_AUDIENCE_INVALID, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("create"), bad_registration).await;
    assert_eq!(
        tt_error_code(&doc),
        CREATE_ERR_REGISTRATION_INVALID,
        "{doc}"
    );

    let id = create(&tv, &chair, body("Fine")).await;
    let u = |extra: Value| {
        let mut p = json!({ "eventId": id });
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        u(json!({ "when": { "start": "2030-01-01T10:00:00", "timeZone": "Nowhere/Land", "duration": "PT1H" } })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_TIME_ZONE_UNKNOWN, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        u(json!({ "when": { "start": "2030-01-01T10:00:00", "timeZone": "Etc/UTC", "duration": "PT5H", "showWithoutTime": true } })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_WHEN_INVALID, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        u(json!({ "audience": { "scope": "roles" } })),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_AUDIENCE_INVALID, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        u(json!({ "registration": { "mode": "open", "waitlist": true } })),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        UPDATE_ERR_REGISTRATION_INVALID,
        "{doc}"
    );
}

/// VTI-EVT-010, 011, 020, 050, 070: an event lands in the community's calendar unless named;
/// a group calendar's event is for the group and takes its default roster; the creator hosts.
#[tokio::test]
async fn vti_evt_011_create_takes_the_calendars_defaults() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (status, doc) = call(&tv, &chair, &uri("create"), body("Meetup")).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let ev = &payload(&doc)["event"];
    assert_eq!(ev["status"], "draft");
    assert_eq!(ev["roster"], "hidden");
    assert_eq!(ev["audience"], json!({ "scope": "members" }));
    assert_eq!(ev["kind"], "event");
    // An administrator who is no member runs the event through their authority and is not
    // appointed (an appointment they granted would go straight to review, VTI-ACL-071)…
    assert!(ev.get("hosts").is_none(), "{doc}");
    // …while a member who runs the calendar is appointed its first host (VTI-EVT-070).
    let organiser = runner(&tv, None).await;
    let (status, doc) = call(&tv, &organiser, &uri("create"), body("Workshop")).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        payload(&doc)["event"]["hosts"],
        json!([entry_of(&tv, &organiser).await]),
        "{doc}"
    );

    let alice = member(&tv).await;
    group_with(&tv, &[&alice]).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "Engineering", "groupId": GROUP, "defaultRoster": "visible", "defaultReminderMinutes": [60] }),
    )
    .await;
    let cal = payload(&doc)["calendar"]["calendarId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "Standup", "when": when_in(2), "calendarId": cal }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let ev = &payload(&doc)["event"];
    assert_eq!(
        ev["audience"],
        json!({ "scope": "groups", "groups": [GROUP] })
    );
    assert_eq!(ev["roster"], "visible");
    assert_eq!(ev["suggestedReminderMinutes"], json!([60]));
    assert!(audit_changes(&tv).await.contains(&"created".to_string()));
}

/// VTI-EVT-014: an archived calendar takes no new event, and its drafts are not published.
#[tokio::test]
async fn vti_evt_014_an_archived_calendar_takes_no_events() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "Old" }),
    )
    .await;
    let cal = payload(&doc)["calendar"]["calendarId"]
        .as_str()
        .unwrap()
        .to_string();
    let draft = create(
        &tv,
        &chair,
        json!({ "title": "Draft", "when": when_in(5), "calendarId": cal }),
    )
    .await;
    let (status, _) = call(
        &tv,
        &chair,
        &uri("calendars/update"),
        json!({ "calendarId": cal, "state": "archived" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "New", "when": when_in(5), "calendarId": cal }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_CALENDAR_ARCHIVED, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("publish"), json!({ "eventId": draft })).await;
    assert_eq!(tt_error_code(&doc), PUBLISH_ERR_CALENDAR_ARCHIVED, "{doc}");
}

/// VTI-EVT-080: the community's events policy may refuse a creation, a change and a
/// publication; it never widens.
#[tokio::test]
async fn vti_evt_080_the_events_policy_may_refuse() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let draft = create(&tv, &chair, body("A meetup")).await;
    activate_events_policy(&tv, DENY_PUBLISH).await;

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "AGM", "when": when_in(3), "kind": "meeting" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_POLICY_REFUSED, "{doc}");
    // The policy reads the event as it would be: kind is fixed, so refuse via a
    // policy over the title instead for the update and the publication.
    activate_events_policy(
        &tv,
        r#"package vtc.events
import rego.v1
default decision := {"effect": "deny", "with": {"reason": "closed for the holidays"}}
"#,
    )
    .await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": draft, "title": "Renamed" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_POLICY_REFUSED, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("publish"), json!({ "eventId": draft })).await;
    assert_eq!(tt_error_code(&doc), PUBLISH_ERR_POLICY_REFUSED, "{doc}");
}

/// VTI-EVT-050 – 052: the roster setting changes freely in a draft, and is fixed once
/// published; each registration records the setting it was made under.
#[tokio::test]
async fn vti_evt_051_roster_is_fixed_at_publish() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let id = create(&tv, &chair, body("Workshop")).await;
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "roster": "visible" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    publish(&tv, &chair, &id).await;
    // The same value is no change.
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "roster": "visible" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "roster": "hidden" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_ROSTER_LOCKED, "{doc}");
    let (status, doc) = register(&tv, &alice, &id, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["registration"]["roster"], "visible");
}

/// VTI-EVT-004, 006, 093: draft → published → cancelled; a draft is deleted and a published
/// event cancelled, never the other way; an ended event is neither published nor cancelled;
/// a change of time after publication moves `sequence`.
#[tokio::test]
async fn vti_evt_004_the_lifecycle() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let draft = create(&tv, &chair, body("Draft")).await;
    let (_, doc) = call(&tv, &chair, &uri("cancel"), json!({ "eventId": draft })).await;
    assert_eq!(tt_error_code(&doc), CANCEL_ERR_NOT_PUBLISHED, "{doc}");

    let live = published(&tv, &chair, body("Live")).await;
    let (_, doc) = call(&tv, &chair, &uri("publish"), json!({ "eventId": live })).await;
    assert_eq!(tt_error_code(&doc), PUBLISH_ERR_NOT_DRAFT, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("delete"), json!({ "eventId": live })).await;
    assert_eq!(tt_error_code(&doc), DELETE_ERR_NOT_DRAFT, "{doc}");

    // VTI-EVT-006: the time moves, the sequence does; the title alone does not.
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": live, "title": "Live, renamed" }),
    )
    .await;
    assert_eq!(payload(&doc)["event"]["sequence"], 0, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": live, "when": when_in(9) }),
    )
    .await;
    assert_eq!(payload(&doc)["event"]["sequence"], 1, "{doc}");

    let (status, doc) = call(
        &tv,
        &chair,
        &uri("cancel"),
        json!({ "eventId": live, "reason": "Venue flooded." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["event"]["status"], "cancelled");
    assert_eq!(payload(&doc)["event"]["cancelReason"], "Venue flooded.");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": live, "title": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_EVENT_CANCELLED, "{doc}");

    // Ended events.
    let past_draft = create(&tv, &chair, json!({ "title": "Past", "when": when_in(-3) })).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("publish"),
        json!({ "eventId": past_draft }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), PUBLISH_ERR_EVENT_ENDED, "{doc}");
    let ended = published(&tv, &chair, body("Ended")).await;
    move_to_past(&tv, &ended).await;
    let (_, doc) = call(&tv, &chair, &uri("cancel"), json!({ "eventId": ended })).await;
    assert_eq!(tt_error_code(&doc), CANCEL_ERR_EVENT_ENDED, "{doc}");

    let (status, doc) = call(&tv, &chair, &uri("delete"), json!({ "eventId": draft })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(&tv, &chair, &uri("show"), json!({ "eventId": draft })).await;
    assert_not_found(&doc);
    let changes = audit_changes(&tv).await;
    for c in ["published", "cancelled", "deleted", "updated"] {
        assert!(changes.contains(&c.to_string()), "{c}: {changes:?}");
    }
}

/// VTI-EVT-004, 020 – 023: a draft is the hosts' alone; the audience is checked live by
/// group, role and rule; an unlisted event is shown by its identifier and left out of the
/// list; a registrant still sees an event after leaving its audience.
#[tokio::test]
async fn vti_evt_021_who_sees_an_event() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;
    group_with(&tv, &[&alice]).await;

    let draft = create(&tv, &chair, body("Draft")).await;
    let (_, doc) = call(&tv, &alice, &uri("show"), json!({ "eventId": draft })).await;
    assert_not_found(&doc);

    let for_group = published(
        &tv,
        &chair,
        json!({ "title": "Engineering only", "when": when_in(4), "audience": { "scope": "groups", "groups": [GROUP] } }),
    )
    .await;
    let (status, _) = call(&tv, &alice, &uri("show"), json!({ "eventId": for_group })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = call(&tv, &bob, &uri("show"), json!({ "eventId": for_group })).await;
    assert_not_found(&doc);

    let for_role = published(
        &tv,
        &chair,
        json!({ "title": "Members", "when": when_in(4), "audience": { "scope": "roles", "roles": ["member"] } }),
    )
    .await;
    let (status, doc) = call(&tv, &bob, &uri("show"), json!({ "eventId": for_role })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    let by_rule = published(
        &tv,
        &chair,
        json!({ "title": "Old hands", "when": when_in(4), "audience": { "scope": "members", "rule": { "all": [{ "fact": "joinedAt", "op": "before", "value": "2000-01-01" }] } } }),
    )
    .await;
    let (_, doc) = call(&tv, &bob, &uri("show"), json!({ "eventId": by_rule })).await;
    assert_not_found(&doc);

    let unlisted = published(
        &tv,
        &chair,
        json!({ "title": "Quiet", "when": when_in(4), "listed": false }),
    )
    .await;
    let (status, _) = call(&tv, &bob, &uri("show"), json!({ "eventId": unlisted })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = call(&tv, &bob, &uri("list"), json!({})).await;
    let ids: Vec<&str> = payload(&doc)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["event"]["eventId"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&unlisted.as_str()), "{doc}");
    assert!(ids.contains(&for_role.as_str()), "{doc}");
    assert!(!ids.contains(&for_group.as_str()), "{doc}");

    // Alice registers, then leaves the group: she still sees her event.
    let (status, doc) = register(&tv, &alice, &for_group, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    vtc_service::groups::remove(tv.state.directory.ks(), GROUP)
        .await
        .unwrap();
    let (status, doc) = call(&tv, &alice, &uri("show"), json!({ "eventId": for_group })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["myRegistration"]["status"], "going");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("show"),
        json!({ "eventId": UNKNOWN_EVENT }),
    )
    .await;
    assert_not_found(&doc);
}

/// VTI-EVT-022: the list is ordered by start, filtered by range, calendar, kind and `mine`;
/// a range runs forward, at most 400 days.
#[tokio::test]
async fn vti_evt_022_list_ranges_filters_and_order() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let later = published(
        &tv,
        &chair,
        json!({ "title": "Later", "when": when_in(20) }),
    )
    .await;
    let sooner = published(
        &tv,
        &chair,
        json!({ "title": "Sooner", "when": when_in(2) }),
    )
    .await;
    let meeting = published(
        &tv,
        &chair,
        json!({ "title": "AGM", "when": when_in(10), "kind": "meeting" }),
    )
    .await;

    let (_, doc) = call(&tv, &alice, &uri("list"), json!({})).await;
    let ids: Vec<String> = payload(&doc)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["event"]["eventId"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec![sooner.clone(), meeting.clone(), later.clone()]);

    let from = stamp(Utc::now() + Duration::days(5));
    let to = stamp(Utc::now() + Duration::days(15));
    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "from": from, "to": to })).await;
    let items = payload(&doc)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["event"]["eventId"], meeting.as_str());

    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "kind": "meeting" })).await;
    assert_eq!(payload(&doc)["items"].as_array().unwrap().len(), 1);

    register(&tv, &alice, &later, json!({})).await;
    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "mine": true })).await;
    let items = payload(&doc)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1, "{doc}");
    assert_eq!(items[0]["myStatus"], "going");

    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "from": to, "to": from })).await;
    assert_eq!(tt_error_code(&doc), LIST_ERR_RANGE_INVALID, "{doc}");
    let far = stamp(Utc::now() + Duration::days(500));
    let now = stamp(Utc::now());
    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "from": now, "to": far })).await;
    assert_eq!(tt_error_code(&doc), LIST_ERR_RANGE_INVALID, "{doc}");

    // Paging: one at a time, the cursor carries on.
    let (_, doc) = call(&tv, &alice, &uri("list"), json!({ "limit": 1 })).await;
    let next = payload(&doc)["nextCursor"].as_str().unwrap().to_string();
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("list"),
        json!({ "limit": 1, "cursor": next }),
    )
    .await;
    assert_eq!(
        payload(&doc)["items"][0]["event"]["eventId"],
        meeting.as_str()
    );
}

// ─── registrations ───────────────────────────────────────────────────────

/// VTI-EVT-033: capacity counts plus-ones; beyond it a registration is refused, or waitlisted
/// where the event keeps a waitlist; a freed place goes to the first on the waitlist that
/// fits, skipping one that does not.
#[tokio::test]
async fn vti_evt_033_capacity_waitlist_and_promotion() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (a, b, c, d) = (
        member(&tv).await,
        member(&tv).await,
        member(&tv).await,
        member(&tv).await,
    );

    let no_wait = published(
        &tv,
        &chair,
        json!({ "title": "Tiny", "when": when_in(3), "registration": { "mode": "open", "capacity": 1 } }),
    )
    .await;
    assert_eq!(
        register(&tv, &a, &no_wait, json!({})).await.0,
        StatusCode::OK
    );
    let (_, doc) = register(&tv, &b, &no_wait, json!({})).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_FULL, "{doc}");

    let id = published(
        &tv,
        &chair,
        json!({ "title": "Workshop", "when": when_in(3), "registration": { "mode": "open", "capacity": 3, "waitlist": true, "plusOnes": 2 } }),
    )
    .await;
    let (_, doc) = register(&tv, &a, &id, json!({ "guests": 1 })).await;
    assert_eq!(payload(&doc)["registration"]["status"], "going");
    assert_eq!(payload(&doc)["wasCreated"], true);
    assert_eq!(payload(&doc)["event"]["eventId"], id.as_str());
    let (_, doc) = register(&tv, &b, &id, json!({})).await;
    assert_eq!(payload(&doc)["registration"]["status"], "going");
    // Full: c (3 people) and d (1) wait, in order.
    let (_, doc) = register(&tv, &c, &id, json!({ "guests": 2 })).await;
    assert_eq!(
        payload(&doc)["registration"]["status"],
        "waitlisted",
        "{doc}"
    );
    assert_eq!(payload(&doc)["registration"]["waitlistPosition"], 1);
    let (_, doc) = register(&tv, &d, &id, json!({})).await;
    assert_eq!(payload(&doc)["registration"]["waitlistPosition"], 2);

    // b withdraws: one place, c needs three, so d moves up.
    let (status, doc) = call(
        &tv,
        &b,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(status_of(&tv, &d, &id).await, "going");
    assert_eq!(status_of(&tv, &c, &id).await, "waitlisted");
    // a withdraws: three places taken by d's one... two free, c still does not fit? 3 cap: d=1
    // going, so 2 free; c needs 3 — stays. a's guests freed anyway.
    call(
        &tv,
        &a,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status_of(&tv, &c, &id).await, "waitlisted");
    // A larger capacity moves the waitlist.
    let (status, _) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "registration": { "mode": "open", "capacity": 4, "waitlist": true, "plusOnes": 2 } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(status_of(&tv, &c, &id).await, "going");
    assert!(audit_changes(&tv).await.contains(&"promoted".to_string()));
}

/// VTI-EVT-031, 034, 035, 038: what a registration is refused for.
#[tokio::test]
async fn vti_evt_031_register_refusals() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;

    let closed = published(
        &tv,
        &chair,
        json!({ "title": "Info", "when": when_in(3), "registration": { "mode": "closed" } }),
    )
    .await;
    let (_, doc) = register(&tv, &alice, &closed, json!({})).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_NOT_OPEN, "{doc}");

    let later = stamp(Utc::now() + Duration::days(1));
    let not_yet = published(
        &tv,
        &chair,
        json!({ "title": "Soon", "when": when_in(3), "registration": { "mode": "open", "opensAt": later } }),
    )
    .await;
    let (_, doc) = register(&tv, &alice, &not_yet, json!({})).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_WINDOW_CLOSED, "{doc}");

    let full = published(
        &tv,
        &chair,
        json!({ "title": "Workshop", "when": when_in(3), "registration": {
            "mode": "open", "plusOnes": 1,
            "questions": [
                { "questionId": "diet", "label": "Dietary needs", "kind": "choice", "choices": ["none", "vegetarian"], "required": true },
                { "questionId": "photos", "label": "Photos OK?", "kind": "boolean" }
            ],
            "codeOfConduct": { "url": "https://riverside.example/conduct", "sha256": COC_SHA }
        } }),
    )
    .await;
    let (_, doc) = register(&tv, &alice, &full, json!({ "guests": 2 })).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_TOO_MANY_GUESTS, "{doc}");
    let (_, doc) = register(&tv, &alice, &full, json!({ "answers": { "photos": true } })).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_ANSWERS_INVALID, "{doc}");
    let (_, doc) = register(
        &tv,
        &alice,
        &full,
        json!({ "answers": { "diet": "carnivore" } }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_ANSWERS_INVALID, "{doc}");
    let (_, doc) = register(&tv, &alice, &full, json!({ "answers": { "diet": "none" } })).await;
    assert_eq!(
        tt_error_code(&doc),
        REGISTER_ERR_CODE_OF_CONDUCT_REQUIRED,
        "{doc}"
    );
    let (status, doc) = register(
        &tv,
        &alice,
        &full,
        json!({ "answers": { "diet": "vegetarian", "photos": false }, "codeOfConductAcknowledged": COC_SHA, "guests": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        payload(&doc)["registration"]["codeOfConductAcknowledged"],
        COC_SHA
    );

    let approval = published(
        &tv,
        &chair,
        json!({ "title": "Curated", "when": when_in(3), "registration": { "mode": "approval" } }),
    )
    .await;
    let (_, doc) = register(&tv, &alice, &approval, json!({ "status": "maybe" })).await;
    assert_eq!(
        tt_error_code(&doc),
        REGISTER_ERR_MAYBE_NOT_ACCEPTED,
        "{doc}"
    );
    let (_, doc) = register(&tv, &alice, &approval, json!({})).await;
    assert_eq!(payload(&doc)["registration"]["status"], "pending");
    let rid = payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("registrations/decide"),
        json!({ "registrationId": rid, "decision": "decline", "note": "Full of speakers." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = register(&tv, &alice, &approval, json!({})).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_HOST_DECIDED, "{doc}");

    let cancelled = published(&tv, &chair, body("Off")).await;
    call(&tv, &chair, &uri("cancel"), json!({ "eventId": cancelled })).await;
    let (_, doc) = register(&tv, &alice, &cancelled, json!({})).await;
    assert_eq!(tt_error_code(&doc), REGISTER_ERR_EVENT_CANCELLED, "{doc}");
}

/// VTI-EVT-037, 092: withdrawal is always allowed, a repeat changes nothing, and the reply is
/// the registrant's receipt.
#[tokio::test]
async fn vti_evt_037_withdrawal_is_always_allowed() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let id = published(&tv, &chair, body("Talk")).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_NOT_REGISTERED, "{doc}");
    register(&tv, &alice, &id, json!({})).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(payload(&doc)["changed"], true, "{doc}");
    assert_eq!(payload(&doc)["registration"]["status"], "withdrawn");
    assert_eq!(payload(&doc)["event"]["title"], "Talk");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(payload(&doc)["changed"], false, "{doc}");
    // A withdrawn registration is re-opened by registering again.
    let (_, doc) = register(&tv, &alice, &id, json!({})).await;
    assert_eq!(payload(&doc)["registration"]["status"], "going");
    assert_eq!(payload(&doc)["wasCreated"], false);
    // Withdrawal from a cancelled event is allowed.
    call(&tv, &chair, &uri("cancel"), json!({ "eventId": id })).await;
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

/// VTI-EVT-053, 073: hosts read every registration; on a visible roster a registrant going or
/// maybe reads who else is; a hidden roster is shown to nobody but the hosts.
#[tokio::test]
async fn vti_evt_053_who_sees_the_roster() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (alice, bob, carol) = (member(&tv).await, member(&tv).await, member(&tv).await);
    let hidden = published(&tv, &chair, body("Hidden")).await;
    register(&tv, &alice, &hidden, json!({})).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("registrations/list"),
        json!({ "eventId": hidden }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), REG_LIST_ERR_ROSTER_HIDDEN, "{doc}");
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("registrations/list"),
        json!({ "eventId": hidden }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["view"], "host");
    assert_eq!(payload(&doc)["registrations"].as_array().unwrap().len(), 1);

    let visible = published(
        &tv,
        &chair,
        json!({ "title": "Visible", "when": when_in(3), "roster": "visible" }),
    )
    .await;
    register(&tv, &alice, &visible, json!({})).await;
    register(&tv, &bob, &visible, json!({ "status": "maybe" })).await;
    let (status, doc) = call(
        &tv,
        &bob,
        &uri("registrations/list"),
        json!({ "eventId": visible }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["view"], "roster");
    let roster = payload(&doc)["roster"].as_array().unwrap().clone();
    assert_eq!(roster.len(), 2);
    assert!(roster.iter().all(|r| r.get("answers").is_none()));
    let (_, doc) = call(
        &tv,
        &carol,
        &uri("registrations/list"),
        json!({ "eventId": visible }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), REG_LIST_ERR_NOT_REGISTERED, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("registrations/list"),
        json!({ "eventId": visible, "statuses": ["going"] }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        REG_LIST_ERR_FILTER_NOT_PERMITTED,
        "{doc}"
    );
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("registrations/list"),
        json!({ "eventId": visible, "statuses": ["maybe"] }),
    )
    .await;
    assert_eq!(
        payload(&doc)["registrations"].as_array().unwrap().len(),
        1,
        "{doc}"
    );
}

/// VTI-EVT-073: hosts decide pending registrations and remove registrations, within the
/// event's capacity and life.
#[tokio::test]
async fn vti_evt_073_hosts_decide_and_remove() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Curated", "when": when_in(3), "registration": { "mode": "approval", "capacity": 1 } }),
    )
    .await;
    let (_, doc) = register(&tv, &alice, &id, json!({})).await;
    let ra = payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, doc) = register(&tv, &bob, &id, json!({})).await;
    let rb = payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("registrations/decide"),
        json!({ "registrationId": ra, "decision": "approve" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["registration"]["status"], "going");
    assert_eq!(payload(&doc)["decision"], "approve");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("registrations/decide"),
        json!({ "registrationId": ra, "decision": "approve" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_NOT_PENDING, "{doc}");
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("registrations/decide"),
        json!({ "registrationId": rb, "decision": "approve" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_FULL, "{doc}");

    // A member cannot decide.
    let (status, _) = call(
        &tv,
        &bob,
        &uri("registrations/decide"),
        json!({ "registrationId": rb, "decision": "approve" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);

    let (status, doc) = call(
        &tv,
        &chair,
        &uri("registrations/remove"),
        json!({ "registrationId": ra, "note": "Code of conduct." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["changed"], true);
    assert_eq!(payload(&doc)["registration"]["status"], "removed");

    call(&tv, &chair, &uri("cancel"), json!({ "eventId": id })).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("registrations/decide"),
        json!({ "registrationId": rb, "decision": "approve" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), DECIDE_ERR_EVENT_CANCELLED, "{doc}");

    let past = published(&tv, &chair, body("Past")).await;
    let (_, doc) = register(&tv, &alice, &past, json!({})).await;
    let rp = payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string();
    move_to_past(&tv, &past).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("registrations/remove"),
        json!({ "registrationId": rp }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), REMOVE_ERR_EVENT_ENDED, "{doc}");
}

/// VTI-EVT-060 – 063: where it happens is released to registrants who are going, from
/// `revealAt`; hosts always read it; a public one is shown with the event.
#[tokio::test]
async fn vti_evt_060_access_details_are_released() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (alice, bob) = (member(&tv).await, member(&tv).await);
    let access =
        json!({ "places": [{ "name": "The Makerspace", "address": "Unit 4, Mill Lane" }] });
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Workshop", "when": when_in(3), "access": access }),
    )
    .await;
    let (_, doc) = call(&tv, &alice, &uri("show"), json!({ "eventId": id })).await;
    assert!(payload(&doc)["event"].get("access").is_none(), "{doc}");
    let (_, doc) = call(&tv, &alice, &uri("access/show"), json!({ "eventId": id })).await;
    assert_eq!(tt_error_code(&doc), ACCESS_ERR_NOT_GOING, "{doc}");
    register(&tv, &alice, &id, json!({ "status": "maybe" })).await;
    let (_, doc) = call(&tv, &alice, &uri("access/show"), json!({ "eventId": id })).await;
    assert_eq!(tt_error_code(&doc), ACCESS_ERR_NOT_GOING, "{doc}");
    register(&tv, &alice, &id, json!({})).await;
    let (status, doc) = call(&tv, &alice, &uri("access/show"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        payload(&doc)["access"]["places"][0]["name"],
        "The Makerspace"
    );
    let (status, _) = call(&tv, &chair, &uri("access/show"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK);

    let reveal = stamp(Utc::now() + Duration::days(2));
    let later = published(
        &tv,
        &chair,
        json!({ "title": "Secret", "when": when_in(3), "access": { "notes": "Door code 4719", "revealAt": reveal } }),
    )
    .await;
    register(&tv, &bob, &later, json!({})).await;
    let (_, doc) = call(&tv, &bob, &uri("access/show"), json!({ "eventId": later })).await;
    assert_eq!(tt_error_code(&doc), ACCESS_ERR_NOT_YET, "{doc}");
    call(&tv, &chair, &uri("cancel"), json!({ "eventId": later })).await;
    let (_, doc) = call(&tv, &bob, &uri("access/show"), json!({ "eventId": later })).await;
    assert_eq!(tt_error_code(&doc), ACCESS_ERR_EVENT_CANCELLED, "{doc}");

    let public = published(
        &tv,
        &chair,
        json!({ "title": "Open day", "when": when_in(3), "access": { "places": [{ "name": "Town hall" }], "public": true } }),
    )
    .await;
    let (_, doc) = call(&tv, &bob, &uri("show"), json!({ "eventId": public })).await;
    assert_eq!(
        payload(&doc)["event"]["access"]["places"][0]["name"],
        "Town hall"
    );
}

// ─── hosts ───────────────────────────────────────────────────────────────

/// VTI-EVT-070 – 072: hosts are appointed active members; an appointed host runs the event;
/// a published event keeps a host.
#[tokio::test]
async fn vti_evt_070_hosts_by_appointment() {
    let tv = community().await;
    // A member who runs the community's calendars, so they are appointed the first host.
    let chair = runner(&tv, None).await;
    let alice = member(&tv).await;
    let id = published(&tv, &chair, body("Meetup")).await;
    let (_, doc) = call(&tv, &alice, &uri("hosts/list"), json!({ "eventId": id })).await;
    let hosts = payload(&doc)["hosts"].as_array().unwrap().clone();
    assert_eq!(hosts.len(), 1, "{doc}");
    let chair_entry = hosts[0].as_str().unwrap().to_string();
    let alice_entry = entry_of(&tv, &alice).await;

    // Before her appointment Alice may not change it.
    let (status, _) = call(
        &tv,
        &alice,
        &uri("update"),
        json!({ "eventId": id, "title": "x" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("hosts/appoint"),
        json!({ "eventId": id, "entryId": "dir_NobodyNobodyNobody0" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), APPOINT_ERR_NOT_ELIGIBLE, "{doc}");
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("hosts/appoint"),
        json!({ "eventId": id, "entryId": alice_entry }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["hosts"].as_array().unwrap().len(), 2);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("hosts/appoint"),
        json!({ "eventId": id, "entryId": alice_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), APPOINT_ERR_ALREADY_HOST, "{doc}");

    // The appointed host runs it.
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("update"),
        json!({ "eventId": id, "title": "Meetup, hosted by Alice" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    let (_, doc) = call(
        &tv,
        &alice,
        &uri("hosts/remove"),
        json!({ "eventId": id, "entryId": "dir_NobodyNobodyNobody0" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), HOSTS_REMOVE_ERR_NOT_HOST, "{doc}");
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("hosts/remove"),
        json!({ "eventId": id, "entryId": chair_entry }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("hosts/remove"),
        json!({ "eventId": id, "entryId": alice_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), HOSTS_REMOVE_ERR_LAST_HOST, "{doc}");

    call(&tv, &alice, &uri("cancel"), json!({ "eventId": id })).await;
    let bob = member(&tv).await;
    let bob_entry = entry_of(&tv, &bob).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("hosts/appoint"),
        json!({ "eventId": id, "entryId": bob_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), APPOINT_ERR_EVENT_CANCELLED, "{doc}");
    let changes = audit_changes(&tv).await;
    assert!(changes.contains(&"hostAppointed".to_string()));
    assert!(changes.contains(&"hostRemoved".to_string()));
}

/// VTI-EVT-095: the portal's key signs a member's registration, never a host's act — even for
/// a member who hosts.
#[tokio::test]
async fn vti_evt_095_the_portal_key_registers_but_never_hosts() {
    let tv = community().await;
    let host = runner(&tv, None).await;
    let id = published(&tv, &host, body("Meetup")).await;

    let k_b = Party::new();
    let now = vti_common::auth::session::now_epoch();
    let session: vti_common::auth::session::Session = serde_json::from_value(json!({
        "session_id": "sess-events-portal",
        "did": host.did,
        "challenge": "c",
        "state": "Authenticated",
        "created_at": now,
        "refresh_token": null,
        "refresh_expires_at": now + 3600,
        "not_after": now + 3600,
        "session_pubkey_b58btc": k_b.did.strip_prefix("did:key:").unwrap(),
    }))
    .unwrap();
    vti_common::auth::session::store_session(&tv.state.member_sessions_ks, &session)
        .await
        .unwrap();
    vtc_service::member_portal::delegation::record(
        &tv.state.member_sessions_ks,
        &k_b.did,
        &vtc_service::member_portal::delegation::Delegation {
            member_did: host.did.clone(),
            session_id: "sess-events-portal".into(),
            scope: vec!["vtc/events".into()],
            not_after: now + 3600,
            grant_id: Some("urn:uuid:events-portal-grant".into()),
        },
    )
    .await
    .unwrap();

    let (status, doc) = register(&tv, &k_b, &id, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, doc) = call(&tv, &k_b, &uri("cancel"), json!({ "eventId": id })).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    let (status, doc) = call(&tv, &host, &uri("cancel"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

// ─── the member's own ────────────────────────────────────────────────────

/// VTI-EVT-092 and the member's agent's sync: `mine/list` answers the caller's registrations
/// with the event as a receipt names it, filtered by status and by change.
#[tokio::test]
async fn vti_evt_092_mine_lists_the_callers_registrations() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let a = published(&tv, &chair, body("A")).await;
    let b = published(&tv, &chair, body("B")).await;
    register(&tv, &alice, &a, json!({})).await;
    register(&tv, &alice, &b, json!({ "status": "maybe" })).await;
    let (status, doc) = call(&tv, &alice, &uri("mine/list"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["items"].as_array().unwrap().len(), 2);
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("mine/list"),
        json!({ "statuses": ["maybe"] }),
    )
    .await;
    let items = payload(&doc)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["event"]["eventId"], b.as_str());

    let mark = stamp(Utc::now() + Duration::seconds(1));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": a, "when": when_in(8) }),
    )
    .await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("mine/list"),
        json!({ "updatedSince": mark }),
    )
    .await;
    let items = payload(&doc)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1, "{doc}");
    assert_eq!(items[0]["event"]["eventId"], a.as_str());
    assert_eq!(items[0]["event"]["sequence"], 1);
}

// ─── reports ─────────────────────────────────────────────────────────────

/// VTI-EVT-081: a member reports an event once, within the community's daily limit.
#[tokio::test]
async fn vti_evt_081_reports() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let a = published(&tv, &chair, body("A")).await;
    let b = published(&tv, &chair, body("B")).await;
    tv.state.config.write().await.events.reports_per_day = 1;
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("report"),
        json!({ "eventId": a, "reason": "spam", "note": "Advertising." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let report = payload(&doc)["reportId"].as_str().unwrap().to_string();
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("report"),
        json!({ "eventId": a, "reason": "spam" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), REPORT_ERR_ALREADY_REPORTED, "{doc}");
    assert_eq!(doc["payload"]["details"]["reportId"], report.as_str());
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("report"),
        json!({ "eventId": b, "reason": "unsafe" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), REPORT_ERR_LIMIT_REACHED, "{doc}");
    assert!(audit_changes(&tv).await.contains(&"reported".to_string()));
}

// ─── phase 2: invitations, links, opt-outs, announcements, partners ──────

const SEND_ERR_NOT_PUBLISHED: &str = e::invitations::send::v0_1::error_codes::NOT_PUBLISHED.code;
const SEND_ERR_EVENT_CANCELLED: &str =
    e::invitations::send::v0_1::error_codes::EVENT_CANCELLED.code;
const SEND_ERR_NOT_ELIGIBLE: &str = e::invitations::send::v0_1::error_codes::NOT_ELIGIBLE.code;
const SEND_ERR_NOT_IN_AUDIENCE: &str =
    e::invitations::send::v0_1::error_codes::NOT_IN_AUDIENCE.code;
const SEND_ERR_MEMBERS_MAY_NOT_INVITE: &str =
    e::invitations::send::v0_1::error_codes::MEMBERS_MAY_NOT_INVITE.code;
const SEND_ERR_LIMIT_REACHED: &str = e::invitations::send::v0_1::error_codes::LIMIT_REACHED.code;
const RESPOND_ERR_NOT_INVITED: &str = e::invitations::respond::v0_1::error_codes::NOT_INVITED.code;
const RESPOND_ERR_EVENT_CANCELLED: &str =
    e::invitations::respond::v0_1::error_codes::EVENT_CANCELLED.code;
const RESPOND_ERR_NOT_OPEN: &str = e::invitations::respond::v0_1::error_codes::NOT_OPEN.code;
const RESPOND_ERR_WINDOW_CLOSED: &str =
    e::invitations::respond::v0_1::error_codes::WINDOW_CLOSED.code;
const RESPOND_ERR_FULL: &str = e::invitations::respond::v0_1::error_codes::FULL.code;
const RESPOND_ERR_TOO_MANY_GUESTS: &str =
    e::invitations::respond::v0_1::error_codes::TOO_MANY_GUESTS.code;
const RESPOND_ERR_ANSWERS_INVALID: &str =
    e::invitations::respond::v0_1::error_codes::ANSWERS_INVALID.code;
const RESPOND_ERR_CODE_OF_CONDUCT_REQUIRED: &str =
    e::invitations::respond::v0_1::error_codes::CODE_OF_CONDUCT_REQUIRED.code;
const RESPOND_ERR_MAYBE_NOT_ACCEPTED: &str =
    e::invitations::respond::v0_1::error_codes::MAYBE_NOT_ACCEPTED.code;
const RESPOND_ERR_HOST_DECIDED: &str =
    e::invitations::respond::v0_1::error_codes::HOST_DECIDED.code;
const LINKS_CREATE_ERR_EVENT_CANCELLED: &str =
    e::invitations::links::create::v0_1::error_codes::EVENT_CANCELLED.code;
const LINKS_CREATE_ERR_EXPIRY_INVALID: &str =
    e::invitations::links::create::v0_1::error_codes::EXPIRY_INVALID.code;
const LINKS_REVOKE_ERR_LINK_NOT_FOUND: &str =
    e::invitations::links::revoke::v0_1::error_codes::LINK_NOT_FOUND.code;
const LINKS_REVOKE_ERR_ALREADY_REVOKED: &str =
    e::invitations::links::revoke::v0_1::error_codes::ALREADY_REVOKED.code;
const LINKS_REDEEM_ERR_LINK_INVALID: &str =
    e::invitations::links::redeem::v0_1::error_codes::LINK_INVALID.code;
const ANN_SEND_ERR_NOT_PUBLISHED: &str =
    e::announcements::send::v0_1::error_codes::NOT_PUBLISHED.code;
const ANN_SEND_ERR_LIMIT_REACHED: &str =
    e::announcements::send::v0_1::error_codes::LIMIT_REACHED.code;
const ANN_LIST_ERR_NOT_REGISTERED: &str =
    e::announcements::list::v0_1::error_codes::NOT_REGISTERED.code;
const CREATE_ERR_PARTNER_INVALID: &str = e::create::v0_2::error_codes::PARTNER_INVALID.code;
const UPDATE_ERR_PARTNER_INVALID: &str = e::update::v0_2::error_codes::PARTNER_INVALID.code;

/// `host` invites `who` to `id` by name.
async fn invite_by_name(tv: &TestVtc, host: &Party, id: &str, who: &Party) {
    let entry = entry_of(tv, who).await;
    let (status, doc) = call(
        tv,
        host,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": [entry] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

/// A published event `host` invites `who` to, by name, from `body`.
async fn invited_to(tv: &TestVtc, host: &Party, who: &Party, body: Value) -> String {
    let id = published(tv, host, body).await;
    invite_by_name(tv, host, &id, who).await;
    id
}

async fn respond(tv: &TestVtc, who: &Party, id: &str, extra: Value) -> (StatusCode, Value) {
    let mut p = json!({ "eventId": id, "answer": "going" });
    if let Value::Object(m) = extra {
        for (k, v) in m {
            p[k] = v;
        }
    }
    call(tv, who, &uri("invitations/respond"), p).await
}

async fn invitation(
    tv: &TestVtc,
    event: &str,
    entry: &str,
) -> Option<vtc_service::community_events::invitations::Invitation> {
    vtc_service::community_events::invitations::get_invitation(&tv.state.events_ks, event, entry)
        .await
        .unwrap()
}

/// VTI-EVT-100 – 102, 108, 110; VTI-NTF-064, 065: under `notify`, the one sender invites each
/// member of the audience once — never one registered or opted out — records it before
/// sending, raises a revision when the event's sequence moves and withdraws it on cancellation.
#[tokio::test]
async fn vti_evt_101_the_sweeper_invites_the_audience_and_keeps_notifications_in_step() {
    use vtc_service::community_events::invitations as inv;
    let tv = community().await;
    let chair = runner(&tv, None).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;
    let carol = member(&tv).await;
    let id = create(
        &tv,
        &chair,
        json!({ "title": "Build night", "when": when_in(7), "invite": "notify" }),
    )
    .await;
    // Nothing is invited while it is a draft.
    inv::settle(&tv.state, Utc::now()).await.unwrap();
    assert!(
        inv::invitations_of(&tv.state.events_ks, &id)
            .await
            .unwrap()
            .is_empty()
    );
    publish(&tv, &chair, &id).await;
    let (status, doc) = register(&tv, &bob, &id, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, doc) = call(
        &tv,
        &carol,
        &uri("optouts/set"),
        json!({ "scope": "event", "eventId": id, "optedOut": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["optedOut"], true);
    let (_, doc) = call(&tv, &carol, &uri("optouts/list"), json!({})).await;
    assert_eq!(payload(&doc)["items"][0]["eventId"], json!(id));

    inv::settle(&tv.state, Utc::now()).await.unwrap();
    inv::settle(&tv.state, Utc::now()).await.unwrap();
    let a = invitation(&tv, &id, &entry_of(&tv, &alice).await)
        .await
        .expect("alice is invited");
    assert_eq!(a.invited_by, inv::Inviter::Audience);
    assert!(!a.reply_expected);
    assert_eq!(a.notice.revision, 1);
    assert!(
        invitation(&tv, &id, &entry_of(&tv, &bob).await)
            .await
            .is_none(),
        "bob registered"
    );
    assert!(
        invitation(&tv, &id, &entry_of(&tv, &carol).await)
            .await
            .is_none(),
        "carol opted out"
    );
    assert_eq!(
        inv::invitations_of(&tv.state.events_ks, &id)
            .await
            .unwrap()
            .iter()
            .filter(|i| i.entry_id == a.entry_id)
            .count(),
        1,
        "at most one invitation per member (VTI-EVT-102)"
    );

    // VTI-NTF-064: the notification carries the reference and the period, never the title.
    let ev = vtc_service::community_events::get_event(&tv.state.events_ks, &id)
        .await
        .unwrap()
        .unwrap();
    let n = inv::payload("did:example:community", &ev, &a.did, &a.notice);
    assert_eq!(n["notification"]["kind"], "event");
    assert_eq!(n["notification"]["subject"]["id"], json!(id));
    assert!(n["notification"]["validFrom"].is_string());
    assert!(!n.to_string().contains("Build night"));
    let schema =
        vti_specs::schema_index::schema_for(vta_sdk::trust_tasks::TASK_NOTIFICATIONS_NOTIFY_0_1)
            .unwrap();
    trust_tasks_rs::validate::against_schema(schema, &n).expect("a valid notify payload");

    // VTI-NTF-065: a change of time is a new revision; a cancellation withdraws it.
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "when": when_in(8) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    inv::settle(&tv.state, Utc::now()).await.unwrap();
    let a = invitation(&tv, &id, &a.entry_id).await.unwrap();
    assert_eq!((a.notice.revision, a.notice.sequence), (2, 1));
    let (status, _) = call(&tv, &chair, &uri("cancel"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK);
    inv::settle(&tv.state, Utc::now()).await.unwrap();
    let a = invitation(&tv, &id, &a.entry_id).await.unwrap();
    assert!(a.notice.withdrawn);
    assert_eq!(a.notice.revision, 3);
}

/// VTI-EVT-103, 105: a host invites any active member, and the invitation puts them in the
/// audience; a member invites only where the event lets them, only its audience, within the
/// daily limit.
#[tokio::test]
async fn vti_evt_103_host_and_member_invitations() {
    let tv = community().await;
    let chair = runner(&tv, None).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;
    let dave = member(&tv).await;
    group_with(&tv, &[&alice, &dave]).await;
    let for_group = json!({ "scope": "groups", "groups": [GROUP] });

    // A draft and a cancelled event invite nobody.
    let draft = create(
        &tv,
        &chair,
        json!({ "title": "Draft", "when": when_in(7), "audience": for_group }),
    )
    .await;
    let bob_entry = entry_of(&tv, &bob).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/send"),
        json!({ "eventId": draft, "entryIds": [bob_entry] }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SEND_ERR_NOT_PUBLISHED, "{doc}");
    let gone = published(&tv, &chair, json!({ "title": "Gone", "when": when_in(7) })).await;
    call(&tv, &chair, &uri("cancel"), json!({ "eventId": gone })).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/send"),
        json!({ "eventId": gone, "entryIds": [bob_entry] }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SEND_ERR_EVENT_CANCELLED, "{doc}");

    // Bob is outside the group's audience until a host invites him by name.
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Group night", "when": when_in(7), "audience": for_group }),
    )
    .await;
    let (_, doc) = call(&tv, &bob, &uri("show"), json!({ "eventId": id })).await;
    assert_not_found(&doc);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": ["dir_NotAMember0000000"] }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SEND_ERR_NOT_ELIGIBLE, "{doc}");
    invite_by_name(&tv, &chair, &id, &bob).await;
    let (status, doc) = call(&tv, &bob, &uri("show"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, doc) = register(&tv, &bob, &id, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    // The hosts see who invited whom and each answer (VTI-EVT-106).
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/list"),
        json!({ "eventId": id }),
    )
    .await;
    let items = payload(&doc)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["invitation"]["invitedBy"], "host");
    assert_eq!(items[0]["invitation"]["answer"], "going");
    assert!(items[0]["invitation"]["inviterEntryId"].is_string());
    let (_, doc) = call(&tv, &bob, &uri("invitations/list"), json!({})).await;
    assert_eq!(payload(&doc)["items"][0]["event"]["eventId"], json!(id));
    assert!(
        payload(&doc)["items"][0]["invitation"]
            .get("inviterEntryId")
            .is_none()
    );

    // Members may not invite unless the event says so.
    let dave_entry = entry_of(&tv, &dave).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": [dave_entry] }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        SEND_ERR_MEMBERS_MAY_NOT_INVITE,
        "{doc}"
    );
    let (status, _) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "membersMayInvite": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // …and then only the audience (VTI-EVT-105).
    let carol = member(&tv).await;
    let carol_entry = entry_of(&tv, &carol).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": [carol_entry] }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SEND_ERR_NOT_IN_AUDIENCE, "{doc}");
    tv.state.config.write().await.events.invitations_per_day = 1;
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": [dave_entry] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["invitations"][0]["invitedBy"], "member");
    let alice_entry = entry_of(&tv, &alice).await;
    let (_, doc) = call(
        &tv,
        &dave,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": [alice_entry] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let erin = member(&tv).await;
    group_with(&tv, &[&alice, &dave, &erin]).await;
    let erin_entry = entry_of(&tv, &erin).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("invitations/send"),
        json!({ "eventId": id, "entryIds": [erin_entry] }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), SEND_ERR_LIMIT_REACHED, "{doc}");
    assert!(audit_changes(&tv).await.iter().any(|c| c == "invited"));
}

/// VTI-EVT-104: an invitee answers going or maybe by registering, under respond's own refusal
/// codes, or declines, which registers nothing and is no host's decline.
#[tokio::test]
async fn vti_evt_104_answering_an_invitation() {
    let tv = community().await;
    let chair = runner(&tv, None).await;
    let alice = member(&tv).await;

    // No invitation.
    let id = published(&tv, &chair, body("Open night")).await;
    let (_, doc) = respond(&tv, &alice, &id, json!({})).await;
    assert_eq!(tt_error_code(&doc), RESPOND_ERR_NOT_INVITED, "{doc}");

    // Decline: recorded on the invitation, nothing registered.
    invite_by_name(&tv, &chair, &id, &alice).await;
    let (status, doc) = respond(&tv, &alice, &id, json!({ "answer": "decline" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["invitation"]["answer"], "declined");
    assert!(payload(&doc).get("registration").is_none());
    assert_eq!(status_of(&tv, &alice, &id).await, "none");
    // Going registers, as register does.
    let (status, doc) = respond(&tv, &alice, &id, json!({ "answer": "going" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["registration"]["status"], "going");
    assert_eq!(payload(&doc)["invitation"]["answer"], "going");

    // Each refusal, under respond's codes.
    let refuses = |reg: Value| json!({ "title": "R", "when": when_in(7), "registration": reg });
    let cases: Vec<(Value, Value, &str)> = vec![
        (json!({ "mode": "closed" }), json!({}), RESPOND_ERR_NOT_OPEN),
        (
            json!({ "mode": "approval" }),
            json!({ "answer": "maybe" }),
            RESPOND_ERR_MAYBE_NOT_ACCEPTED,
        ),
        (
            json!({ "mode": "open", "plusOnes": 0 }),
            json!({ "guests": 2 }),
            RESPOND_ERR_TOO_MANY_GUESTS,
        ),
        (
            json!({ "mode": "open", "questions": [{ "questionId": "diet", "label": "Diet", "kind": "text", "required": true }] }),
            json!({}),
            RESPOND_ERR_ANSWERS_INVALID,
        ),
        (
            json!({ "mode": "open", "codeOfConduct": { "url": "https://example.org/coc", "sha256": COC_SHA } }),
            json!({}),
            RESPOND_ERR_CODE_OF_CONDUCT_REQUIRED,
        ),
        (
            json!({ "mode": "open", "closesAt": stamp(Utc::now() + Duration::hours(1)) }),
            json!({}),
            "window",
        ),
    ];
    for (reg, extra, code) in cases {
        let id = invited_to(&tv, &chair, &alice, refuses(reg)).await;
        if code == "window" {
            let ks = &tv.state.events_ks;
            let mut ev = vtc_service::community_events::get_event(ks, &id)
                .await
                .unwrap()
                .unwrap();
            ev.registration["closesAt"] = json!(stamp(Utc::now() - Duration::hours(1)));
            vtc_service::community_events::put_event(ks, &ev)
                .await
                .unwrap();
            let (_, doc) = respond(&tv, &alice, &id, extra).await;
            assert_eq!(tt_error_code(&doc), RESPOND_ERR_WINDOW_CLOSED, "{doc}");
            continue;
        }
        let (_, doc) = respond(&tv, &alice, &id, extra).await;
        assert_eq!(tt_error_code(&doc), code, "{doc}");
    }
    // Full.
    let bob = member(&tv).await;
    let id = invited_to(&tv, &chair, &alice, json!({ "title": "Tiny", "when": when_in(7), "registration": { "mode": "open", "capacity": 1 } })).await;
    register(&tv, &bob, &id, json!({})).await;
    let (_, doc) = respond(&tv, &alice, &id, json!({})).await;
    assert_eq!(tt_error_code(&doc), RESPOND_ERR_FULL, "{doc}");
    // A host decided it.
    let id = invited_to(&tv, &chair, &alice, body("Removed")).await;
    let (_, doc) = respond(&tv, &alice, &id, json!({})).await;
    let rid = payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &tv,
        &chair,
        &uri("registrations/remove"),
        json!({ "registrationId": rid }),
    )
    .await;
    let (_, doc) = respond(&tv, &alice, &id, json!({})).await;
    assert_eq!(tt_error_code(&doc), RESPOND_ERR_HOST_DECIDED, "{doc}");
    // Cancelled.
    let id = invited_to(&tv, &chair, &alice, body("Off")).await;
    call(&tv, &chair, &uri("cancel"), json!({ "eventId": id })).await;
    let (_, doc) = respond(&tv, &alice, &id, json!({})).await;
    assert_eq!(tt_error_code(&doc), RESPOND_ERR_EVENT_CANCELLED, "{doc}");
}

/// VTI-EVT-107: a link's code is answered once and kept as a digest; redeeming it invites the
/// member as a host would; every failure is the same refusal.
#[tokio::test]
async fn vti_evt_107_invitation_links() {
    let tv = community().await;
    let chair = runner(&tv, None).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;
    group_with(&tv, &[&bob]).await;
    let id = published(&tv, &chair, json!({ "title": "Secret supper", "when": when_in(7), "audience": { "scope": "groups", "groups": [GROUP] } })).await;

    let (_, doc) = call(&tv, &chair, &uri("invitations/links/create"), json!({ "eventId": id, "maxRedemptions": 1, "expiresAt": stamp(Utc::now() - Duration::hours(1)) })).await;
    assert_eq!(
        tt_error_code(&doc),
        LINKS_CREATE_ERR_EXPIRY_INVALID,
        "{doc}"
    );
    let (status, doc) = call(&tv, &chair, &uri("invitations/links/create"), json!({ "eventId": id, "label": "Flyer", "maxRedemptions": 1, "expiresAt": stamp(Utc::now() + Duration::days(2)) })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let code = payload(&doc)["code"].as_str().unwrap().to_string();
    let link_id = payload(&doc)["link"]["linkId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(code.len() >= 43);
    assert!(
        !tv.state
            .events_ks
            .prefix_iter_raw(Vec::new())
            .await
            .unwrap()
            .iter()
            .any(|(_, v)| String::from_utf8_lossy(v).contains(&code)),
        "the code is never stored"
    );

    // Alice is outside the audience; the link invites her as a host would.
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("invitations/links/redeem"),
        json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["invitation"]["invitedBy"], "link");
    let (status, _) = call(&tv, &alice, &uri("show"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK);
    // Spent, twice, unknown: one refusal.
    for (who, c) in [
        (&bob, code.as_str()),
        (&alice, code.as_str()),
        (&bob, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ] {
        let (_, doc) = call(
            &tv,
            who,
            &uri("invitations/links/redeem"),
            json!({ "code": c }),
        )
        .await;
        assert_eq!(tt_error_code(&doc), LINKS_REDEEM_ERR_LINK_INVALID, "{doc}");
    }

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/links/revoke"),
        json!({ "eventId": id, "linkId": "lnk_AAAAAAAAAAAAAAAAAAAAAA" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        LINKS_REVOKE_ERR_LINK_NOT_FOUND,
        "{doc}"
    );
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("invitations/links/revoke"),
        json!({ "eventId": id, "linkId": link_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(payload(&doc)["link"]["revokedAt"].is_string());
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/links/revoke"),
        json!({ "eventId": id, "linkId": link_id }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        LINKS_REVOKE_ERR_ALREADY_REVOKED,
        "{doc}"
    );

    call(&tv, &chair, &uri("cancel"), json!({ "eventId": id })).await;
    let (_, doc) = call(&tv, &chair, &uri("invitations/links/create"), json!({ "eventId": id, "maxRedemptions": 1, "expiresAt": stamp(Utc::now() + Duration::days(1)) })).await;
    assert_eq!(
        tt_error_code(&doc),
        LINKS_CREATE_ERR_EVENT_CANCELLED,
        "{doc}"
    );
}

/// VTI-EVT-120, 121: hosts post announcements within a daily limit; registrants read them; the
/// event is marked changed without its sequence moving.
#[tokio::test]
async fn vti_evt_120_announcements() {
    let tv = community().await;
    let chair = runner(&tv, None).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;
    let draft = create(&tv, &chair, body("Draft")).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("announcements/send"),
        json!({ "eventId": draft, "text": "Hello" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), ANN_SEND_ERR_NOT_PUBLISHED, "{doc}");

    let id = published(&tv, &chair, body("Talk")).await;
    register(&tv, &alice, &id, json!({})).await;
    let before = vtc_service::community_events::get_event(&tv.state.events_ks, &id)
        .await
        .unwrap()
        .unwrap();
    tv.state.config.write().await.events.announcements_per_day = 1;
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("announcements/send"),
        json!({ "eventId": id, "text": "Bring a laptop" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let after = vtc_service::community_events::get_event(&tv.state.events_ks, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.sequence, before.sequence, "VTI-EVT-121");
    assert!(after.updated_at >= before.updated_at);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("announcements/send"),
        json!({ "eventId": id, "text": "Again" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), ANN_SEND_ERR_LIMIT_REACHED, "{doc}");

    let (status, doc) = call(
        &tv,
        &alice,
        &uri("announcements/list"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["items"][0]["text"], "Bring a laptop");
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("announcements/list"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), ANN_LIST_ERR_NOT_REGISTERED, "{doc}");
}

/// VTI-EVT-130, 133: a partner is a member community or one in a relationship in force;
/// another is refused. A party who is not a member and whose presentation does not pass sees
/// nothing.
#[tokio::test]
async fn vti_evt_130_partners_are_checked() {
    let tv = community().await;
    let chair = runner(&tv, None).await;
    let stranger = "did:web:not-a-partner.example";
    let (_, doc) = call(&tv, &chair, &uri("create"), json!({ "title": "Joint", "when": when_in(7), "audience": { "scope": "members", "partners": [stranger] } })).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_PARTNER_INVALID, "{doc}");
    assert_eq!(payload(&doc)["details"]["partner"], stranger);

    // A member community holding our membership credential is a partner.
    let partner = member(&tv).await;
    let mut m = vtc_service::members::get_member(&tv.state.members_ks, &partner.did)
        .await
        .unwrap()
        .unwrap();
    m.current_vmc_id = Some("urn:uuid:5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into());
    vtc_service::members::store_member(&tv.state.members_ks, &m)
        .await
        .unwrap();
    let id = published(&tv, &chair, json!({ "title": "Joint", "when": when_in(7), "audience": { "scope": "members", "partners": [partner.did] } })).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "audience": { "scope": "members", "partners": [stranger] } }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_PARTNER_INVALID, "{doc}");

    // VTI-EVT-131: one notification to the partner, at its own DID.
    vtc_service::community_events::invitations::settle(&tv.state, Utc::now())
        .await
        .unwrap();
    let notices =
        vtc_service::community_events::invitations::partner_notices(&tv.state.events_ks, &id)
            .await
            .unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].partner, partner.did);

    // VTI-EVT-133: a non-member whose presentation does not pass sees what a stranger would.
    let outsider = Party::new();
    let (_, doc) = call(
        &tv,
        &outsider,
        &uri("show"),
        json!({ "eventId": id, "presentation": "not.a.presentation~" }),
    )
    .await;
    assert_not_found(&doc);
}
