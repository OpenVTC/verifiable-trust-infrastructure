//! Community events, phase 4 (`vtc/events/*`, VTI-EVT-140 – 186): an event's own identity,
//! guests, the door (challenges and check-in), tickets and attendance.
//!
//! The community's VTA is a stand-in, as in `groups.rs`: it mints a `did:key` identity and
//! answers `keys/sign-document` with the document it was given and a proof. Every declared
//! refusal of the phase-4 tasks is driven here and asserted by its code (the error-code census
//! names these tests).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vtc_service::acl::VtcRole;
use vtc_service::community_events as ce;
use vtc_service::config::GroupsConfig;
use vtc_service::rooms::vta_storage::{PeerError, VtaChannel};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{admin, call, party_with_role, payload};

use vti_specs::vtc::events as e;

const CREATE_ERR_BADGE_NOT_FOUND: &str = e::create::v0_3::error_codes::BADGE_NOT_FOUND.code;
const CREATE_ERR_NO_KEY_HOLDER: &str = e::create::v0_3::error_codes::NO_KEY_HOLDER.code;
const CREATE_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    e::create::v0_3::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const UPDATE_ERR_BADGE_NOT_FOUND: &str = e::update::v0_3::error_codes::BADGE_NOT_FOUND.code;
const LINKS_CREATE_ERR_GUESTS_NOT_ADMITTED: &str =
    e::invitations::links::create::v0_2::error_codes::GUESTS_NOT_ADMITTED.code;
const CHALLENGE_ERR_NOT_PUBLISHED: &str =
    e::checkin::challenge::v0_1::error_codes::NOT_PUBLISHED.code;
const CHALLENGE_ERR_EVENT_CANCELLED: &str =
    e::checkin::challenge::v0_1::error_codes::EVENT_CANCELLED.code;
const CHALLENGE_ERR_EVENT_ENDED: &str = e::checkin::challenge::v0_1::error_codes::EVENT_ENDED.code;
const CHECKIN_ERR_ALREADY_CHECKED_IN: &str =
    e::checkin::record::v0_1::error_codes::ALREADY_CHECKED_IN.code;
const CHECKIN_ERR_CHALLENGE_INVALID: &str =
    e::checkin::record::v0_1::error_codes::CHALLENGE_INVALID.code;
const CHECKIN_ERR_EVENT_CANCELLED: &str =
    e::checkin::record::v0_1::error_codes::EVENT_CANCELLED.code;
const CHECKIN_ERR_NOT_DURING_EVENT: &str =
    e::checkin::record::v0_1::error_codes::NOT_DURING_EVENT.code;
const CHECKIN_ERR_NOT_GOING: &str = e::checkin::record::v0_1::error_codes::NOT_GOING.code;
const CHECKIN_ERR_SELF_NOT_ALLOWED: &str =
    e::checkin::record::v0_1::error_codes::SELF_CHECK_IN_NOT_ALLOWED.code;
const TICKETS_ERR_NO_TICKETS: &str = e::tickets::show::v0_1::error_codes::NO_TICKETS.code;
const TICKETS_ERR_NOT_GOING: &str = e::tickets::show::v0_1::error_codes::NOT_GOING.code;
const ATTENDANCE_ERR_RANGE_INVALID: &str =
    e::attendance::show::v0_1::error_codes::RANGE_INVALID.code;
const GUEST_ERR_ALREADY_MEMBER: &str = e::guests::register::v0_1::error_codes::ALREADY_MEMBER.code;
const GUEST_ERR_ANSWERS_INVALID: &str =
    e::guests::register::v0_1::error_codes::ANSWERS_INVALID.code;
const GUEST_ERR_CODE_OF_CONDUCT_REQUIRED: &str =
    e::guests::register::v0_1::error_codes::CODE_OF_CONDUCT_REQUIRED.code;
const GUEST_ERR_EVENT_CANCELLED: &str =
    e::guests::register::v0_1::error_codes::EVENT_CANCELLED.code;
const GUEST_ERR_FULL: &str = e::guests::register::v0_1::error_codes::FULL.code;
const GUEST_ERR_GUESTS_NOT_ADMITTED: &str =
    e::guests::register::v0_1::error_codes::GUESTS_NOT_ADMITTED.code;
const GUEST_ERR_HOST_DECIDED: &str = e::guests::register::v0_1::error_codes::HOST_DECIDED.code;
const GUEST_ERR_MAYBE_NOT_ACCEPTED: &str =
    e::guests::register::v0_1::error_codes::MAYBE_NOT_ACCEPTED.code;
const GUEST_ERR_NOT_OPEN: &str = e::guests::register::v0_1::error_codes::NOT_OPEN.code;
const GUEST_ERR_TOO_MANY_GUESTS: &str =
    e::guests::register::v0_1::error_codes::TOO_MANY_GUESTS.code;
const GUEST_ERR_WINDOW_CLOSED: &str = e::guests::register::v0_1::error_codes::WINDOW_CLOSED.code;
const GUEST_WITHDRAW_ERR_NOT_REGISTERED: &str =
    e::guests::withdraw::v0_1::error_codes::NOT_REGISTERED.code;

const SPEC: &str = "https://trusttasks.org/spec/";
const GROUP: &str = "grp_EngineeringGroup0001";
const COC_SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const MINT: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.2";
const SIGN_DOCUMENT: &str = "https://trusttasks.org/spec/keys/sign-document/0.1";

/// The served version of each task this file sends.
fn uri(task: &str) -> String {
    let v = match task {
        "create" | "update" | "show" | "publish" | "cancel" => "0.3",
        "registrations/register"
        | "registrations/withdraw"
        | "registrations/decide"
        | "calendars/create"
        | "invitations/links/create" => "0.2",
        _ => "0.1",
    };
    format!("{SPEC}vtc/events/{task}/{v}")
}

fn tt_error_code(doc: &Value) -> &str {
    doc.pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A `when` starting `days` from now, an hour long, in UTC.
fn when_in(days: i64) -> Value {
    let start = (Utc::now() + Duration::days(days)).format("%Y-%m-%dT%H:%M:%S");
    json!({ "start": start.to_string(), "timeZone": "Etc/UTC", "duration": "PT1H" })
}

// ─── the community's VTA, standing in ───────────────────────────────────

#[derive(Clone)]
enum Script {
    Silent,
    Refuse(&'static str),
}

#[derive(Default)]
struct VtaState {
    calls: Vec<(String, Value)>,
    scripted: HashMap<String, Script>,
}

#[derive(Clone, Default)]
struct FakeVta(Arc<Mutex<VtaState>>);

impl FakeVta {
    fn script(&self, type_uri: &str, s: Script) {
        self.0
            .lock()
            .unwrap()
            .scripted
            .insert(type_uri.to_string(), s);
    }

    fn calls_of(&self, type_uri: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(t, _)| t == type_uri)
            .map(|(_, p)| p.clone())
            .collect()
    }
}

fn reply(type_uri: &str, payload: Value) -> TrustTask<Value> {
    serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "issuer": "did:example:community-vta",
        "recipient": TEST_VTC_DID,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": payload,
    }))
    .unwrap()
}

#[async_trait]
impl VtaChannel for FakeVta {
    async fn exchange(
        &self,
        type_uri: &str,
        payload: &Value,
        _timeout: StdDuration,
    ) -> Result<TrustTask<Value>, PeerError> {
        let scripted = {
            let mut st = self.0.lock().unwrap();
            st.calls.push((type_uri.to_string(), payload.clone()));
            st.scripted.remove(type_uri)
        };
        match scripted {
            Some(Script::Silent) => {
                return Err(PeerError::Transient("no answer within the timeout".into()));
            }
            Some(Script::Refuse(code)) => {
                return Ok(reply(
                    "https://trusttasks.org/spec/trust-task-error/0.5",
                    json!({ "code": code, "message": "refused by the stand-in" }),
                ));
            }
            None => {}
        }
        let answer = match type_uri {
            MINT => {
                let did = Party::new().did;
                json!({
                    "did": did,
                    "contextId": payload["contextId"],
                    "scid": "QmScid",
                    "portable": true,
                    "signingKeyId": format!("{did}#key-1"),
                    "kaKeyId": format!("{did}#key-2"),
                    "preRotationKeyCount": 0,
                    "createdAt": Utc::now().to_rfc3339(),
                    "serverId": payload["serverId"],
                })
            }
            SIGN_DOCUMENT => {
                let mut document = payload["document"].clone();
                document["proof"] = json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": payload["keyId"],
                    "proofPurpose": "assertionMethod",
                    "created": Utc::now().to_rfc3339(),
                    "proofValue": "z3a4b5c6d7e8f9",
                });
                json!({
                    "proof": document["proof"].clone(),
                    "document": document,
                    "keyId": payload["keyId"],
                    "signerDid": payload["document"]["issuer"],
                })
            }
            other => panic!("the stand-in serves no {other}"),
        };
        Ok(reply(&format!("{type_uri}#response"), answer))
    }
}

// ─── fixtures ────────────────────────────────────────────────────────────

/// A community with events, optionally a VTA holding identities' keys.
async fn community_with(vta: Option<&FakeVta>) -> TestVtc {
    let mut builder = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url("https://vtc.example.com")
        .with_signers(true)
        .with_audit(true)
        .with_groups(GroupsConfig {
            context: Some("vtc".into()),
            webvh_server: Some("hosting".into()),
            ..Default::default()
        });
    if let Some(v) = vta {
        builder = builder.with_community_key_holder(Arc::new(v.clone()));
    }
    let tv = builder.build().await;
    vtc_service::status_list::ensure_initial(
        &tv.state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        "https://vtc.example.com/v1/status-lists/revocation".to_string(),
    )
    .await
    .unwrap();
    vtc_service::policy::default::install_defaults(
        &tv.state.policies_ks,
        &tv.state.active_policies_ks,
    )
    .await
    .unwrap();
    tv
}

async fn community() -> TestVtc {
    community_with(None).await
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

async fn create(tv: &TestVtc, who: &Party, body: Value) -> String {
    let (status, doc) = call(tv, who, &uri("create"), body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["event"]["eventId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn published(tv: &TestVtc, who: &Party, body: Value) -> String {
    let id = create(tv, who, body).await;
    let (status, doc) = call(tv, who, &uri("publish"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    id
}

async fn cancel(tv: &TestVtc, who: &Party, id: &str) {
    let (status, doc) = call(tv, who, &uri("cancel"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

/// Register `who`, going; the registration's identifier.
async fn going(tv: &TestVtc, who: &Party, id: &str) -> String {
    let (status, doc) = call(
        tv,
        who,
        &uri("registrations/register"),
        json!({ "eventId": id, "status": "going" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Move a stored event so it began `minutes_ago` and runs an hour, as time passing would.
async fn start_ago(tv: &TestVtc, id: &str, minutes_ago: i64) {
    let ks = &tv.state.events_ks;
    let mut ev = ce::get_event(ks, id).await.unwrap().unwrap();
    let start = (Utc::now() - Duration::minutes(minutes_ago)).format("%Y-%m-%dT%H:%M:%S");
    ev.when = serde_json::from_value(
        json!({ "start": start.to_string(), "timeZone": "Etc/UTC", "duration": "PT1H" }),
    )
    .unwrap();
    ce::put_event(ks, &ev).await.unwrap();
}

async fn event_count(tv: &TestVtc) -> usize {
    ce::events(&tv.state.events_ks).await.unwrap().len()
}

// ─── identity (VTI-EVT-140 – 145) ────────────────────────────────────────

/// VTI-EVT-141, 142: an event's identity is minted from `vtc-event` and authorised by the
/// community before the event is stored; cancelling revokes the authority.
#[tokio::test]
async fn vti_evt_141_an_event_identity_is_minted_before_it_is_stored() {
    let vta = FakeVta::default();
    let tv = community_with(Some(&vta)).await;
    let chair = admin(&tv).await;
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Hack night", "when": when_in(7), "identity": true }),
    )
    .await;
    let mint = vta.calls_of(MINT);
    assert_eq!(mint.len(), 1);
    assert_eq!(mint[0]["template"], "vtc-event");
    let signed = vta.calls_of(SIGN_DOCUMENT);
    assert_eq!(signed.len(), 1);
    let vac = &signed[0]["document"];
    assert_eq!(vac["issuer"], TEST_VTC_DID);
    assert!(vac["credentialStatus"].is_object(), "{vac}");
    assert!(
        vac.to_string().contains("issue-tickets"),
        "the authority grants issuing tickets: {vac}"
    );

    let (_, doc) = call(&tv, &chair, &uri("show"), json!({ "eventId": id })).await;
    let did = payload(&doc)["event"]["identity"]["did"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(vac["credentialSubject"]["id"], did.as_str());
    assert!(
        payload(&doc)["event"]["identity"]["authorityValidUntil"].is_string(),
        "a host sees the authority's expiry: {doc}"
    );
    // A member sees the identity, never its authority's expiry.
    let alice = member(&tv).await;
    let (_, doc) = call(&tv, &alice, &uri("show"), json!({ "eventId": id })).await;
    assert_eq!(payload(&doc)["event"]["identity"]["did"], did.as_str());
    assert!(
        payload(&doc)["event"]["identity"]
            .get("authorityValidUntil")
            .is_none()
    );

    cancel(&tv, &chair, &id).await;
    let ev = ce::get_event(&tv.state.events_ks, &id)
        .await
        .unwrap()
        .unwrap();
    assert!(ev.identity.unwrap().revoked_at.is_some(), "cancel revokes");
}

/// VTI-EVT-141: Remote first — no key holder, an unanswered mint, or a refused authority store
/// nothing.
#[tokio::test]
async fn vti_evt_141_an_identity_that_cannot_be_made_stores_nothing() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "Hack night", "when": when_in(7), "identity": true }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_NO_KEY_HOLDER, "{doc}");
    assert_eq!(event_count(&tv).await, 0);

    let vta = FakeVta::default();
    let tv = community_with(Some(&vta)).await;
    let chair = admin(&tv).await;
    vta.script(MINT, Script::Silent);
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "Hack night", "when": when_in(7), "identity": true }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CREATE_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    assert_eq!(event_count(&tv).await, 0);

    // Minted, but the authority refused: the DID it minted is named, nothing kept.
    vta.script(SIGN_DOCUMENT, Script::Refuse("forbidden"));
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "Hack night", "when": when_in(7), "identity": true }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        CREATE_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    assert_eq!(event_count(&tv).await, 0);

    // Without an identity, no VTA is asked.
    let before = vta.calls_of(MINT).len();
    create(&tv, &chair, json!({ "title": "Plain", "when": when_in(7) })).await;
    assert_eq!(vta.calls_of(MINT).len(), before);
}

/// VTI-EVT-186: an attendance badge names an active community badge.
#[tokio::test]
async fn vti_evt_186_the_attendance_badge_is_a_community_badge() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("create"),
        json!({ "title": "Meetup", "when": when_in(7), "attendanceBadge": "bdg_NoSuchBadge00000001" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_BADGE_NOT_FOUND, "{doc}");
    let id = create(
        &tv,
        &chair,
        json!({ "title": "Meetup", "when": when_in(7) }),
    )
    .await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("update"),
        json!({ "eventId": id, "attendanceBadge": "bdg_NoSuchBadge00000001" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_BADGE_NOT_FOUND, "{doc}");
}

// ─── the door (VTI-EVT-160 – 166) ────────────────────────────────────────

/// VTI-EVT-160, 161: a door challenge is issued by door staff for a published event that has
/// not ended.
#[tokio::test]
async fn vti_evt_161_door_challenges() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let draft = create(&tv, &chair, json!({ "title": "Draft", "when": when_in(7) })).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("checkin/challenge"),
        json!({ "eventId": draft }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHALLENGE_ERR_NOT_PUBLISHED, "{doc}");

    let off = published(&tv, &chair, json!({ "title": "Off", "when": when_in(7) })).await;
    cancel(&tv, &chair, &off).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("checkin/challenge"),
        json!({ "eventId": off }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHALLENGE_ERR_EVENT_CANCELLED, "{doc}");

    let past = published(&tv, &chair, json!({ "title": "Past", "when": when_in(7) })).await;
    start_ago(&tv, &past, 24 * 60).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("checkin/challenge"),
        json!({ "eventId": past }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHALLENGE_ERR_EVENT_ENDED, "{doc}");

    let id = published(&tv, &chair, json!({ "title": "On", "when": when_in(7) })).await;
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("checkin/challenge"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let challenge = payload(&doc)["challenge"].as_str().unwrap();
    assert!(challenge.len() >= 22, "{challenge}");
    assert!(payload(&doc)["expiresAt"].is_string());
    // Only door staff: a member is answered as if there were no such event.
    let (status, _) = call(
        &tv,
        &alice,
        &uri("checkin/challenge"),
        json!({ "eventId": id }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
}

/// VTI-EVT-162, 163, 165: check-in over a door challenge and by door staff, once, for a
/// registrant who is going; the check-in list is door staff's.
#[tokio::test]
async fn vti_evt_162_check_in_over_a_challenge_and_by_staff() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;
    let carol = member(&tv).await;
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Build night", "when": when_in(7) }),
    )
    .await;
    going(&tv, &alice, &id).await;
    let carol_reg = going(&tv, &carol, &id).await;

    let (_, doc) = call(
        &tv,
        &chair,
        &uri("checkin/challenge"),
        json!({ "eventId": id }),
    )
    .await;
    let challenge = payload(&doc)["challenge"].as_str().unwrap().to_string();

    // A challenge never issued, and one issued and past its time: one refusal.
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id, "challenge": "AAAAAAAAAAAAAAAAAAAAAA" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_CHALLENGE_INVALID, "{doc}");
    let (stale, _) =
        ce::door::issue_challenge(&tv.state.events_ks, &id, Utc::now() - Duration::minutes(10))
            .await
            .unwrap();
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id, "challenge": stale }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_CHALLENGE_INVALID, "{doc}");

    let (status, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id, "challenge": challenge }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["checkIn"]["method"], "challenge");
    assert_eq!(payload(&doc)["checkIn"]["registrantKind"], "member");
    assert_eq!(payload(&doc)["checkIn"]["counts"], true);
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id, "challenge": challenge }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_ALREADY_CHECKED_IN, "{doc}");
    // Bob never registered.
    let (_, doc) = call(
        &tv,
        &bob,
        &uri("checkin/record"),
        json!({ "eventId": id, "challenge": challenge }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_NOT_GOING, "{doc}");

    // Door staff check Carol in by name.
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("checkin/record"),
        json!({ "eventId": id, "registrationId": carol_reg }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["checkIn"]["method"], "staff");
    assert!(payload(&doc)["checkIn"]["checkedInBy"].is_string(), "{doc}");

    let (status, doc) = call(&tv, &chair, &uri("checkin/list"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["checkedIn"], 2);
    assert_eq!(payload(&doc)["items"].as_array().unwrap().len(), 2);
    let (status, _) = call(&tv, &alice, &uri("checkin/list"), json!({ "eventId": id })).await;
    assert_ne!(status, StatusCode::OK, "the list is door staff's");

    // The member's attendance: one counted event this month.
    let (status, doc) = call(&tv, &alice, &uri("attendance/show"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["total"], 1, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("attendance/show"),
        json!({ "sinceMonth": "2026-12", "untilMonth": "2026-01" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), ATTENDANCE_ERR_RANGE_INVALID, "{doc}");

    // A cancelled event checks nobody in.
    let off = published(&tv, &chair, json!({ "title": "Off", "when": when_in(7) })).await;
    let bob_reg = going(&tv, &bob, &off).await;
    cancel(&tv, &chair, &off).await;
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("checkin/record"),
        json!({ "eventId": off, "registrationId": bob_reg }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_EVENT_CANCELLED, "{doc}");
}

/// VTI-EVT-164, 183: check-in without a challenge only where the calendar allows it, only while
/// the event runs, and it counts only where the calendar says so.
#[tokio::test]
async fn vti_evt_164_self_check_in_follows_the_calendar() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    group_with(&tv, &[&alice]).await;

    // The community's calendar admits no self check-in.
    let id = published(&tv, &chair, json!({ "title": "Talk", "when": when_in(7) })).await;
    going(&tv, &alice, &id).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_SELF_NOT_ALLOWED, "{doc}");

    // A calendar that lets self check-in count.
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("calendars/create"),
        json!({ "name": "Engineering", "groupId": GROUP, "selfCheckIn": "counting" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["calendar"]["selfCheckIn"], "counting");
    let cal = payload(&doc)["calendar"]["calendarId"]
        .as_str()
        .unwrap()
        .to_string();
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Standup", "when": when_in(7), "calendarId": cal }),
    )
    .await;
    going(&tv, &alice, &id).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), CHECKIN_ERR_NOT_DURING_EVENT, "{doc}");
    start_ago(&tv, &id, 10).await;
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["checkIn"]["method"], "self");
    assert_eq!(payload(&doc)["checkIn"]["counts"], true);
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("attendance/show"),
        json!({ "calendarId": cal }),
    )
    .await;
    assert_eq!(payload(&doc)["total"], 1, "{doc}");

    // An event that does not count leaves the tally alone.
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Social", "when": when_in(7), "calendarId": cal, "countsAttendance": false }),
    )
    .await;
    going(&tv, &alice, &id).await;
    start_ago(&tv, &id, 10).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("checkin/record"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(payload(&doc)["checkIn"]["counts"], false, "{doc}");
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("attendance/show"),
        json!({ "calendarId": cal }),
    )
    .await;
    assert_eq!(payload(&doc)["total"], 1, "{doc}");
}

// ─── tickets (VTI-EVT-170 – 174) ─────────────────────────────────────────

/// VTI-EVT-170 – 174: a ticket for a registrant who is going, signed by the event's identity
/// where it has one and by the community otherwise, with a slot in the community's revocation
/// list, revoked when its registrant withdraws.
#[tokio::test]
async fn vti_evt_171_tickets_are_issued_and_revoked() {
    let vta = FakeVta::default();
    let tv = community_with(Some(&vta)).await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let bob = member(&tv).await;

    let plain = published(
        &tv,
        &chair,
        json!({ "title": "No tickets", "when": when_in(7) }),
    )
    .await;
    going(&tv, &alice, &plain).await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("tickets/show"),
        json!({ "eventId": plain }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), TICKETS_ERR_NO_TICKETS, "{doc}");

    let id = published(
        &tv,
        &chair,
        json!({ "title": "Gala", "when": when_in(7), "tickets": true }),
    )
    .await;
    let (_, doc) = call(&tv, &alice, &uri("tickets/show"), json!({ "eventId": id })).await;
    assert_eq!(tt_error_code(&doc), TICKETS_ERR_NOT_GOING, "{doc}");
    going(&tv, &alice, &id).await;
    let (status, doc) = call(&tv, &alice, &uri("tickets/show"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let vc = &payload(&doc)["credential"];
    assert!(vc.to_string().contains("EventTicketCredential"), "{vc}");
    assert_eq!(
        vc["issuer"], TEST_VTC_DID,
        "no identity: the community signs"
    );
    assert!(vc["credentialStatus"].is_object(), "{vc}");
    assert!(vc["proof"].is_object(), "{vc}");
    // Asked again: the same ticket, not a second.
    let signed = vta.calls_of(SIGN_DOCUMENT).len();
    let (_, again) = call(&tv, &alice, &uri("tickets/show"), json!({ "eventId": id })).await;
    assert_eq!(payload(&again)["credential"], *vc);
    assert_eq!(vta.calls_of(SIGN_DOCUMENT).len(), signed);

    // Withdrawing revokes it at the next sweep.
    let (status, doc) = call(
        &tv,
        &alice,
        &uri("registrations/withdraw"),
        json!({ "eventId": id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    ce::tickets::sweep(&tv.state, Utc::now()).await.unwrap();
    let entry = entry_of(&tv, &alice).await;
    let reg = ce::get_registration(&tv.state.events_ks, &id, &entry)
        .await
        .unwrap()
        .unwrap();
    assert!(
        reg.ticket.unwrap().revoked,
        "a withdrawn registrant's ticket is revoked"
    );

    // An event with an identity signs as that identity.
    let id = published(
        &tv,
        &chair,
        json!({ "title": "Summit", "when": when_in(7), "tickets": true, "identity": true }),
    )
    .await;
    going(&tv, &bob, &id).await;
    let (status, doc) = call(&tv, &bob, &uri("tickets/show"), json!({ "eventId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let ev = ce::get_event(&tv.state.events_ks, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        payload(&doc)["credential"]["issuer"],
        ev.identity.unwrap().did.as_str()
    );
}

// ─── guests (VTI-EVT-150 – 154) ──────────────────────────────────────────

/// VTI-EVT-150 – 153: a guest is a party who is not a member, admitted by the event's guest
/// setting — never by its audience — and signing their own requests.
#[tokio::test]
async fn vti_evt_151_guests_register_and_withdraw() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let guest = Party::new();

    let none = published(
        &tv,
        &chair,
        json!({ "title": "Members only", "when": when_in(7) }),
    )
    .await;
    let (_, doc) = call(
        &tv,
        &guest,
        &uri("guests/register"),
        json!({ "eventId": none, "status": "going" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_GUESTS_NOT_ADMITTED, "{doc}");

    let open = published(
        &tv,
        &chair,
        json!({ "title": "Open house", "when": when_in(7), "guests": "open" }),
    )
    .await;
    let (_, doc) = call(
        &tv,
        &alice,
        &uri("guests/register"),
        json!({ "eventId": open, "status": "going" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_ALREADY_MEMBER, "{doc}");
    let (_, doc) = call(
        &tv,
        &guest,
        &uri("guests/withdraw"),
        json!({ "eventId": open }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        GUEST_WITHDRAW_ERR_NOT_REGISTERED,
        "{doc}"
    );
    let (status, doc) = call(
        &tv,
        &guest,
        &uri("guests/register"),
        json!({ "eventId": open, "status": "going" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["wasCreated"], true);
    assert_eq!(payload(&doc)["registration"]["status"], "going");
    // The guest sees the event they registered for.
    let (status, doc) = call(&tv, &guest, &uri("show"), json!({ "eventId": open })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // …and nothing else.
    let (status, _) = call(&tv, &guest, &uri("show"), json!({ "eventId": none })).await;
    assert_ne!(status, StatusCode::OK);
    let (status, doc) = call(
        &tv,
        &guest,
        &uri("guests/withdraw"),
        json!({ "eventId": open }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["registration"]["status"], "withdrawn");

    // `invited`: only a link made for guests admits one, and only for an event admitting them.
    let (_, doc) = call(
        &tv,
        &chair,
        &uri("invitations/links/create"),
        json!({ "eventId": open, "maxRedemptions": 1, "forGuests": true,
                "expiresAt": stamp(Utc::now() + Duration::days(2)) }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        LINKS_CREATE_ERR_GUESTS_NOT_ADMITTED,
        "{doc}"
    );
    let invited = published(
        &tv,
        &chair,
        json!({ "title": "Supper", "when": when_in(7), "guests": "invited" }),
    )
    .await;
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("invitations/links/create"),
        json!({ "eventId": invited, "maxRedemptions": 1, "forGuests": true,
                "expiresAt": stamp(Utc::now() + Duration::days(2)) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["link"]["forGuests"], true);
    let code = payload(&doc)["code"].as_str().unwrap().to_string();
    let friend = Party::new();
    let (_, doc) = call(
        &tv,
        &friend,
        &uri("guests/register"),
        json!({ "eventId": invited, "status": "going" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_GUESTS_NOT_ADMITTED, "{doc}");
    // A member cannot redeem a guest link.
    let (status, _) = call(
        &tv,
        &alice,
        &uri("invitations/links/redeem"),
        json!({ "code": code }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    let (status, doc) = call(
        &tv,
        &friend,
        &uri("guests/register"),
        json!({ "eventId": invited, "status": "going", "linkCode": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // Spent: another guest is not admitted by it.
    let (_, doc) = call(
        &tv,
        &Party::new(),
        &uri("guests/register"),
        json!({ "eventId": invited, "status": "going", "linkCode": code }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_GUESTS_NOT_ADMITTED, "{doc}");
}

/// VTI-EVT-152: a guest's registration is held to the event's registration rules as a
/// member's is, each refused with the guest task's own code.
#[tokio::test]
async fn vti_evt_152_guest_registration_follows_the_rules() {
    let tv = community().await;
    let chair = admin(&tv).await;
    let alice = member(&tv).await;
    let register = |p: Value| {
        let tv = &tv;
        async move {
            let (_, doc) = call(tv, &Party::new(), &uri("guests/register"), p).await;
            doc
        }
    };

    let closed = published(
        &tv,
        &chair,
        json!({ "title": "Info", "when": when_in(3), "guests": "open", "registration": { "mode": "closed" } }),
    )
    .await;
    let doc = register(json!({ "eventId": closed, "status": "going" })).await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_NOT_OPEN, "{doc}");

    let later = stamp(Utc::now() + Duration::days(1));
    let not_yet = published(
        &tv,
        &chair,
        json!({ "title": "Soon", "when": when_in(3), "guests": "open", "registration": { "mode": "open", "opensAt": later } }),
    )
    .await;
    let doc = register(json!({ "eventId": not_yet, "status": "going" })).await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_WINDOW_CLOSED, "{doc}");

    let tiny = published(
        &tv,
        &chair,
        json!({ "title": "Tiny", "when": when_in(3), "guests": "open", "registration": { "mode": "open", "capacity": 1 } }),
    )
    .await;
    going(&tv, &alice, &tiny).await;
    let doc = register(json!({ "eventId": tiny, "status": "going" })).await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_FULL, "{doc}");

    let workshop = published(
        &tv,
        &chair,
        json!({ "title": "Workshop", "when": when_in(3), "guests": "open", "registration": {
            "mode": "open", "plusOnes": 1,
            "questions": [
                { "questionId": "diet", "label": "Dietary needs", "kind": "choice", "choices": ["none", "vegetarian"], "required": true }
            ],
            "codeOfConduct": { "url": "https://riverside.example/conduct", "sha256": COC_SHA }
        } }),
    )
    .await;
    let doc = register(json!({ "eventId": workshop, "status": "going", "guests": 2 })).await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_TOO_MANY_GUESTS, "{doc}");
    let doc = register(
        json!({ "eventId": workshop, "status": "going", "answers": { "diet": "carnivore" } }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_ANSWERS_INVALID, "{doc}");
    let doc =
        register(json!({ "eventId": workshop, "status": "going", "answers": { "diet": "none" } }))
            .await;
    assert_eq!(
        tt_error_code(&doc),
        GUEST_ERR_CODE_OF_CONDUCT_REQUIRED,
        "{doc}"
    );

    let approval = published(
        &tv,
        &chair,
        json!({ "title": "Curated", "when": when_in(3), "guests": "open", "registration": { "mode": "approval" } }),
    )
    .await;
    let doc = register(json!({ "eventId": approval, "status": "maybe" })).await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_MAYBE_NOT_ACCEPTED, "{doc}");
    let declined = Party::new();
    let (_, doc) = call(
        &tv,
        &declined,
        &uri("guests/register"),
        json!({ "eventId": approval, "status": "going" }),
    )
    .await;
    assert_eq!(payload(&doc)["registration"]["status"], "pending", "{doc}");
    let rid = payload(&doc)["registration"]["registrationId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = call(
        &tv,
        &chair,
        &uri("registrations/decide"),
        json!({ "registrationId": rid, "decision": "decline" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = call(
        &tv,
        &declined,
        &uri("guests/register"),
        json!({ "eventId": approval, "status": "going" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_HOST_DECIDED, "{doc}");

    // A guest registered before the event was cancelled is refused with the guest's code.
    let off = published(
        &tv,
        &chair,
        json!({ "title": "Off", "when": when_in(3), "guests": "open" }),
    )
    .await;
    let early = Party::new();
    let (status, doc) = call(
        &tv,
        &early,
        &uri("guests/register"),
        json!({ "eventId": off, "status": "going" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    cancel(&tv, &chair, &off).await;
    let doc = register(json!({ "eventId": off, "status": "going" })).await;
    assert_eq!(tt_error_code(&doc), GUEST_ERR_EVENT_CANCELLED, "{doc}");
}
