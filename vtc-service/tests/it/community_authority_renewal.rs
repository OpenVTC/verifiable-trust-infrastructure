//! Renewing the community's own authority over the rooms it owns
//! (`vtc_service::rooms::community_renewal`): `vtc/rooms/community/create` item 6's
//! SHOULD, through the `rooms/owner/*` and `vault/credentials/*` tasks the community's VTA
//! already serves.
//!
//! The VTA here is a stand-in that keeps a vault the way a real one does — a credential
//! stored under an `id` it already holds replaces it — so a test can ask the one question
//! that matters after a renewal: does the VTA hold exactly one membership and one authority
//! for the community in the room, and are they the new ones?

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vti_rooms_dtg::test_support::Party;

use vtc_service::config::CommunityRoomsConfig;
use vtc_service::rooms::community::OwnedRoom;
use vtc_service::rooms::community_renewal::{self, SweepReport};
use vtc_service::rooms::vta_storage::{PeerError, VtaChannel};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::Gesturer;
use crate::common::signed::{post, signed};

const CREATE: &str = "https://trusttasks.org/spec/vtc/rooms/community/create/0.1";
const GET: &str = "https://trusttasks.org/spec/vtc/rooms/community/get/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/rooms/community/list/0.1";

const MINT: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.1";
const GROUP_CREATE: &str = "https://trusttasks.org/spec/rooms/owner/group/create/0.1";
const ISSUE_MEMBERSHIP: &str = "https://trusttasks.org/spec/rooms/owner/issue-membership/0.1";
const ISSUE_AUTHORITY: &str = "https://trusttasks.org/spec/rooms/owner/issue-authority/0.2";
const RECEIVE: &str = "https://trusttasks.org/spec/vault/credentials/receive/0.1";
const QUERY: &str = "https://trusttasks.org/spec/vault/credentials/query/0.1";
const VAULT_GET: &str = "https://trusttasks.org/spec/vault/credentials/get/0.1";

// ─── the community's VTA, standing in ───────────────────────────────────

#[derive(Clone, Copy)]
enum Script {
    /// No answer: the outcome is unknown.
    Silent,
    /// Serve the request — its effect happens — and then lose the answer.
    ServeThenSilent,
}

#[derive(Default)]
struct VtaState {
    calls: Vec<(String, Value)>,
    /// What to do with the next requests of a type, in order: `None` serves normally.
    scripted: HashMap<String, VecDeque<Option<Script>>>,
    /// The vault: handle → credential.
    vault: HashMap<String, Value>,
}

#[derive(Clone, Default)]
struct FakeVta(Arc<Mutex<VtaState>>);

impl FakeVta {
    fn script(&self, type_uri: &str, steps: &[Option<Script>]) {
        self.0
            .lock()
            .unwrap()
            .scripted
            .insert(type_uri.to_string(), steps.iter().copied().collect());
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.0.lock().unwrap().calls.clone()
    }

    fn clear_calls(&self) {
        self.0.lock().unwrap().calls.clear();
    }

    fn stored(&self, id: &str, credential: Value) {
        self.0
            .lock()
            .unwrap()
            .vault
            .insert(id.to_string(), credential);
    }

    /// Every credential the vault holds of `kind` issued by `room` to `subject`, by handle.
    fn held(&self, room: &str, kind: &str, subject: &str) -> Vec<(String, Value)> {
        let st = self.0.lock().unwrap();
        let mut out: Vec<(String, Value)> = st
            .vault
            .iter()
            .filter(|(_, c)| {
                c["issuer"] == room
                    && c["credentialSubject"]["id"] == subject
                    && c["type"].as_array().unwrap().iter().any(|t| t == kind)
            })
            .map(|(id, c)| (id.clone(), c.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn serve(&self, type_uri: &str, p: &Value) -> Result<Value, (&'static str, String)> {
        match type_uri {
            MINT => {
                let did = format!("did:example:room-{}", uuid::Uuid::new_v4().simple());
                Ok(json!({
                    "did": did,
                    "contextId": p["contextId"],
                    "scid": "QmScid",
                    "portable": true,
                    "signingKeyId": format!("{did}#key-1"),
                    "kaKeyId": format!("{did}#key-2"),
                    "preRotationKeyCount": 0,
                    "createdAt": Utc::now().to_rfc3339(),
                    "serverId": p["serverId"],
                }))
            }
            GROUP_CREATE => Ok(json!({ "roomId": p["roomId"], "epoch": 1 })),
            ISSUE_MEMBERSHIP | ISSUE_AUTHORITY => {
                let tag = if type_uri == ISSUE_MEMBERSHIP {
                    "MembershipCredential"
                } else {
                    "AuthorityCredential"
                };
                let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
                let mut c = credential(
                    p["roomId"].as_str().unwrap(),
                    tag,
                    p["subject"].as_str().unwrap(),
                    p["validUntil"].as_str().unwrap(),
                );
                c["id"] = json!(id);
                if let Some(actions) = p.get("actions") {
                    c["credentialSubject"]["actions"] = actions.clone();
                }
                Ok(json!({ "credential": c.to_string(), "credentialId": id }))
            }
            RECEIVE => {
                let c = p["credential"].clone();
                // `id` absent: the credential's own (`vault/credentials/receive` Definitions).
                let id = p["id"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| c["id"].as_str().unwrap().to_string());
                self.stored(&id, c);
                Ok(json!({ "id": id, "types": ["VerifiableCredential"], "status": "valid" }))
            }
            QUERY => {
                let st = self.0.lock().unwrap();
                let mut credentials: Vec<Value> = st
                    .vault
                    .iter()
                    .filter(|(_, c)| {
                        c["issuer"] == p["issuerDid"]
                            && c["type"].as_array().unwrap().contains(&p["type"])
                    })
                    .map(|(id, c)| json!({ "id": id, "types": c["type"], "status": "valid" }))
                    .collect();
                credentials.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
                Ok(json!({ "credentials": credentials }))
            }
            VAULT_GET => {
                let st = self.0.lock().unwrap();
                match st.vault.get(p["id"].as_str().unwrap()) {
                    Some(c) => Ok(json!({ "credential": c })),
                    None => Err(("vault/credentials/get:notFound", "no such id".into())),
                }
            }
            other => Err(("unsupportedType", format!("{other} is not served here"))),
        }
    }
}

fn credential(room: &str, tag: &str, subject: &str, valid_until: &str) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "DTGCredential", tag],
        "issuer": room,
        "validFrom": Utc::now().to_rfc3339(),
        "validUntil": valid_until,
        "credentialSubject": { "id": subject },
    })
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
        _timeout: Duration,
    ) -> Result<TrustTask<Value>, PeerError> {
        let scripted = {
            let mut st = self.0.lock().unwrap();
            st.calls.push((type_uri.to_string(), payload.clone()));
            st.scripted
                .get_mut(type_uri)
                .and_then(VecDeque::pop_front)
                .flatten()
        };
        match scripted {
            Some(Script::Silent) => {
                return Err(PeerError::Transient("no answer within the timeout".into()));
            }
            Some(Script::ServeThenSilent) => {
                let _ = self.serve(type_uri, payload);
                return Err(PeerError::Transient("the answer was lost".into()));
            }
            None => {}
        }
        Ok(match self.serve(type_uri, payload) {
            Ok(answer) => reply(&format!("{type_uri}#response"), answer),
            Err((code, message)) => reply(
                "https://trusttasks.org/spec/trust-task-error/0.5",
                json!({ "code": code, "message": message }),
            ),
        })
    }
}

// ─── the community ──────────────────────────────────────────────────────

struct Fixture {
    vtc: TestVtc,
    vta: FakeVta,
    admin: Party,
}

fn config() -> CommunityRoomsConfig {
    CommunityRoomsConfig {
        context: "vtc".into(),
        webvh_server: Some("hosting".into()),
        mediator_did: Some("did:example:mediator".into()),
        authority_valid_days: None,
        authority_renew_within_days: None,
    }
}

async fn fixture_with(community: Option<CommunityRoomsConfig>, with_vta: bool) -> Fixture {
    let vta = FakeVta::default();
    let mut builder = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url("https://vtc.example.com")
        .with_signers(true)
        .with_audit(true);
    if let Some(c) = community {
        builder = builder.with_community_rooms(c);
    }
    if with_vta {
        builder = builder.with_community_key_holder(Arc::new(vta.clone()));
    }
    let vtc = builder.build().await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    let admin = crate::common::signed::admin(&vtc).await;
    Fixture { vtc, vta, admin }
}

async fn fixture() -> Fixture {
    fixture_with(Some(config()), true).await
}

/// A room the community owns and hosts, as a create before this release left it: no
/// record of where the VTA keeps the community's credentials.
async fn seed_room(fix: &Fixture, authority_until: DateTime<Utc>) -> String {
    seed_room_owned_by(fix, authority_until, TEST_VTC_DID, None).await
}

async fn seed_room_owned_by(
    fix: &Fixture,
    authority_until: DateTime<Utc>,
    host_owner: &str,
    epoch_expires_at: Option<u64>,
) -> String {
    let room_id = format!("did:example:room-{}", uuid::Uuid::new_v4().simple());
    let at = Utc::now().timestamp() as u64;
    let room = vti_rooms::Room {
        room_id: room_id.clone(),
        owner_did: host_owner.to_string(),
        visibility: vti_rooms::Visibility::Attributed,
        retention_policy: vti_rooms::RetentionPolicy::Chained,
        anchor_cadence: Default::default(),
        epoch: 1,
        next_version: 1,
        retention_days: 1,
        epoch_expires_at: Some(epoch_expires_at.unwrap_or(at + 300 * 24 * 60 * 60)),
        created_at: at,
        updated_at: at,
        mirror_of: None,
    };
    vti_rooms::storage::create_room(&fix.vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    seed_owner_record(fix, &room_id, authority_until).await;
    room_id
}

async fn seed_owner_record(fix: &Fixture, room_id: &str, authority_until: DateTime<Utc>) {
    let owned = OwnedRoom {
        room_id: room_id.to_string(),
        label: "Board pack".into(),
        visibility: "attributed".into(),
        signing_key_id: format!("{room_id}#key-1"),
        created_by: fix.admin.did.clone(),
        created_at: Utc::now().to_rfc3339(),
        owner_authority_valid_until: rfc3339(authority_until),
        did_path: None,
    };
    fix.vtc
        .state
        .community_rooms
        .put_room(&owned)
        .await
        .unwrap();
}

/// Now, to the second: what the community writes back is to the second.
fn whole_now() -> DateTime<Utc> {
    use chrono::Timelike as _;
    Utc::now().with_nanosecond(0).unwrap()
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

async fn owner_until(fix: &Fixture, room: &str) -> DateTime<Utc> {
    let r = fix
        .vtc
        .state
        .community_rooms
        .room(room)
        .await
        .unwrap()
        .unwrap();
    DateTime::parse_from_rfc3339(&r.owner_authority_valid_until)
        .unwrap()
        .with_timezone(&Utc)
}

async fn sweep(fix: &Fixture, now: DateTime<Utc>) -> SweepReport {
    community_renewal::sweep(&fix.vtc.state, now).await.unwrap()
}

async fn audit_rows(fix: &Fixture) -> String {
    let mut out = String::new();
    for (_, raw) in fix
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
    {
        out.push_str(&String::from_utf8_lossy(&raw));
    }
    out
}

/// Exactly one membership and one authority for the community in `room`, both valid until
/// about `until`; answers their handles.
fn assert_one_each(fix: &Fixture, room: &str, until: DateTime<Utc>) -> (String, String) {
    let mut handles = Vec::new();
    for kind in ["MembershipCredential", "AuthorityCredential"] {
        let held = fix.vta.held(room, kind, TEST_VTC_DID);
        assert_eq!(held.len(), 1, "one {kind} for the community: {held:?}");
        let valid_until = DateTime::parse_from_rfc3339(held[0].1["validUntil"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);
        assert!(
            (valid_until - until).num_seconds().abs() <= 1,
            "{kind} valid until {valid_until}, expected {until}"
        );
        handles.push(held[0].0.clone());
    }
    let authority = fix.vta.held(room, "AuthorityCredential", TEST_VTC_DID);
    assert_eq!(
        authority[0].1["credentialSubject"]["actions"],
        json!(["read", "write", "curate", "admin"]),
        "the same scope as create issued"
    );
    (handles[0].clone(), handles[1].clone())
}

async fn get_room(fix: &Fixture, room: &str) -> Value {
    let (status, reply) = post(
        &fix.vtc,
        &signed(&fix.admin, GET, json!({ "roomId": room })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    crate::common::signed::assert_conforms(GET, &reply);
    reply
}

fn types_called(fix: &Fixture) -> Vec<String> {
    fix.vta.calls().into_iter().map(|(t, _)| t).collect()
}

// ─── the tests ──────────────────────────────────────────────────────────

/// A room created now records where the VTA keeps the community's two credentials, and its
/// renewal replaces them there — never a second copy beside the first, which the VTA would
/// refuse to choose between. The new validity is recorded and shown.
#[tokio::test]
async fn a_room_inside_the_window_is_renewed_in_place_and_its_new_validity_recorded() {
    let fix = fixture().await;
    let mut gesturer = Gesturer::new();
    gesturer.enrol(&fix.vtc, &fix.admin.did).await;
    let doc = signed(
        &fix.admin,
        CREATE,
        json!({ "label": "Board pack", "visibility": "attributed", "reason": "the board's papers" }),
    )
    .await;
    let (status, reply) = gesturer.send_through(&fix.vtc, &fix.admin, &[], &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let room = reply["payload"]["room"]["room"]["roomId"]
        .as_str()
        .unwrap()
        .to_string();

    let created_until = owner_until(&fix, &room).await;
    let (membership, authority) = assert_one_each(&fix, &room, created_until);
    let rec = community_renewal::record(&fix.vtc.state.community_rooms, &room)
        .await
        .unwrap()
        .expect("create records where the credentials are kept");
    assert_eq!(
        rec.membership_vault_id.as_deref(),
        Some(membership.as_str())
    );
    assert_eq!(rec.authority_vault_id.as_deref(), Some(authority.as_str()));

    // Twenty days before it lapses: inside the default thirty.
    let now = created_until - chrono::Duration::days(20);
    fix.vta.clear_calls();
    let report = sweep(&fix, now).await;
    assert_eq!(report.renewed, vec![room.clone()]);
    assert!(report.failed.is_empty());

    let new_until = now + chrono::Duration::days(365);
    assert_eq!(owner_until(&fix, &room).await, new_until);
    let after = assert_one_each(&fix, &room, new_until);
    assert_eq!(
        after,
        (membership.clone(), authority.clone()),
        "replaced, by handle"
    );
    // Found from the record: the VTA's vault was not read.
    let called = types_called(&fix);
    assert!(
        !called.iter().any(|t| t == QUERY || t == VAULT_GET),
        "{called:?}"
    );
    let receives: Vec<Value> = fix
        .vta
        .calls()
        .into_iter()
        .filter(|(t, _)| t == RECEIVE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(receives.len(), 2);
    assert_eq!(receives[0]["id"], json!(membership));
    assert_eq!(receives[1]["id"], json!(authority));
    assert_eq!(receives[1]["contextId"], "vtc");

    assert!(audit_rows(&fix).await.contains("authorityRenewed"));
    let got = get_room(&fix, &room).await;
    assert_eq!(
        got["payload"]["room"]["ownerAuthorityValidUntil"],
        json!(rfc3339(new_until))
    );
    let renewal = &got["payload"]["ext"]["org.openvtc"]["authorityRenewal"];
    assert_eq!(renewal["state"], "ok", "{got}");
    assert_eq!(renewal["lastRenewedAt"], json!(rfc3339(now)));
    assert_eq!(renewal["renewWithinDays"], 30);

    // Renewed: no longer due.
    fix.vta.clear_calls();
    assert_eq!(
        sweep(&fix, now + chrono::Duration::hours(1)).await,
        SweepReport::default()
    );
    assert!(fix.vta.calls().is_empty());
}

/// Outside the window nothing is asked of the VTA, and nothing is written.
#[tokio::test]
async fn a_room_outside_the_window_is_not_renewed() {
    let fix = fixture().await;
    let now = whole_now();
    let until = now + chrono::Duration::days(31);
    let room = seed_room(&fix, until).await;
    assert_eq!(sweep(&fix, now).await, SweepReport::default());
    assert!(fix.vta.calls().is_empty());
    assert_eq!(
        owner_until(&fix, &room).await.timestamp(),
        until.timestamp()
    );
    assert!(
        community_renewal::record(&fix.vtc.state.community_rooms, &room)
            .await
            .unwrap()
            .is_none()
    );

    // A configured window is honoured.
    let mut c = config();
    c.authority_renew_within_days = Some(45);
    let fix = fixture_with(Some(c), true).await;
    let room = seed_room(&fix, until).await;
    assert_eq!(sweep(&fix, now).await.renewed, vec![room]);
}

/// The VTA does not answer: the failure is recorded, audited and shown, the owner's record
/// is untouched, nothing is retried before the backoff, and the next attempt after it
/// renews.
#[tokio::test]
async fn an_unreachable_vta_is_retried_after_a_backoff_and_then_renews() {
    let fix = fixture().await;
    let now = whole_now();
    let until = now + chrono::Duration::days(10);
    let room = seed_room(&fix, until).await;
    fix.vta.stored(
        "m-1",
        credential(&room, "MembershipCredential", TEST_VTC_DID, &rfc3339(until)),
    );
    fix.vta.stored(
        "a-1",
        credential(&room, "AuthorityCredential", TEST_VTC_DID, &rfc3339(until)),
    );
    fix.vta.script(ISSUE_MEMBERSHIP, &[Some(Script::Silent)]);

    let report = sweep(&fix, now).await;
    assert_eq!(report.failed, vec![room.clone()]);
    assert_eq!(
        owner_until(&fix, &room).await.timestamp(),
        until.timestamp()
    );
    let rec = community_renewal::record(&fix.vtc.state.community_rooms, &room)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.attempts, 1);
    assert!(
        rec.last_error
            .as_deref()
            .unwrap()
            .contains("could not be reached"),
        "{rec:?}"
    );
    let next = DateTime::parse_from_rfc3339(rec.next_attempt_at.as_deref().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        next >= now + chrono::Duration::seconds(30) && next <= now + chrono::Duration::seconds(60)
    );
    // The handles found on the way are kept.
    assert_eq!(rec.membership_vault_id.as_deref(), Some("m-1"));
    assert_eq!(rec.authority_vault_id.as_deref(), Some("a-1"));
    assert!(audit_rows(&fix).await.contains("authorityRenewalFailed"));

    let got = get_room(&fix, &room).await;
    let renewal = &got["payload"]["ext"]["org.openvtc"]["authorityRenewal"];
    assert_eq!(renewal["state"], "failing", "{got}");
    assert_eq!(renewal["attempts"], 1);
    let (status, listed) = post(&fix.vtc, &signed(&fix.admin, LIST, json!({})).await).await;
    assert_eq!(status, StatusCode::OK);
    crate::common::signed::assert_conforms(LIST, &listed);
    assert_eq!(
        listed["payload"]["ext"]["org.openvtc"]["authorityRenewal"]["rooms"][&room]["state"],
        "failing",
        "{listed}"
    );

    // Not before the backoff.
    fix.vta.clear_calls();
    assert_eq!(
        sweep(&fix, now + chrono::Duration::seconds(20)).await,
        SweepReport::default()
    );
    assert!(fix.vta.calls().is_empty());

    // After it, the VTA answers.
    let later = now + chrono::Duration::minutes(2);
    assert_eq!(sweep(&fix, later).await.renewed, vec![room.clone()]);
    let new_until = later + chrono::Duration::days(365);
    assert_eq!(owner_until(&fix, &room).await, new_until);
    assert_eq!(
        assert_one_each(&fix, &room, new_until),
        ("m-1".into(), "a-1".into())
    );
    let rec = community_renewal::record(&fix.vtc.state.community_rooms, &room)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.attempts, 0);
    assert!(rec.last_error.is_none() && rec.next_attempt_at.is_none());
}

/// The process stops after the VTA stored the new authority and before this community
/// recorded it: a pass in a new process finds the room still due and renews again, under
/// the same handles, so the VTA still holds one of each.
#[tokio::test]
async fn a_renewal_cut_off_mid_way_is_finished_by_the_next_pass() {
    let fix = fixture().await;
    let now = whole_now();
    let until = now + chrono::Duration::days(5);
    let room = seed_room(&fix, until).await;
    fix.vta.stored(
        "m-1",
        credential(&room, "MembershipCredential", TEST_VTC_DID, &rfc3339(until)),
    );
    fix.vta.stored(
        "a-1",
        credential(&room, "AuthorityCredential", TEST_VTC_DID, &rfc3339(until)),
    );
    // The membership is stored and answered; the authority is stored and its answer lost.
    fix.vta
        .script(RECEIVE, &[None, Some(Script::ServeThenSilent)]);

    let report = sweep(&fix, now).await;
    assert_eq!(report.failed, vec![room.clone()]);
    // The VTA holds the new pair already; this community has not committed to it.
    let stored_until = now + chrono::Duration::days(365);
    assert_one_each(&fix, &room, stored_until);
    assert_eq!(
        owner_until(&fix, &room).await.timestamp(),
        until.timestamp()
    );

    // A restart: the next pass runs with nothing but what was persisted.
    let later = now + chrono::Duration::minutes(5);
    assert_eq!(sweep(&fix, later).await.renewed, vec![room.clone()]);
    let new_until = later + chrono::Duration::days(365);
    assert_eq!(
        assert_one_each(&fix, &room, new_until),
        ("m-1".into(), "a-1".into())
    );
    assert_eq!(owner_until(&fix, &room).await, new_until);
}

/// A room this community no longer hosts, one it no longer owns at its host, and one past
/// its retention are not renewed, and nothing is asked of the VTA for them.
#[tokio::test]
async fn retired_rooms_are_not_renewed() {
    let fix = fixture().await;
    let now = whole_now();
    let until = now + chrono::Duration::days(3);
    // Not hosted here any more: only the owner's record is left.
    seed_owner_record(&fix, "did:example:gone", until).await;
    // Transferred away at its host.
    seed_room_owned_by(&fix, until, "did:example:someone-else", None).await;
    // Past its retention: lapsed in 1970.
    seed_room_owned_by(&fix, until, TEST_VTC_DID, Some(1)).await;

    assert_eq!(sweep(&fix, now).await, SweepReport::default());
    assert!(fix.vta.calls().is_empty(), "{:?}", types_called(&fix));
}

/// A room created before renewal recorded where its credentials are kept: they are found
/// in the VTA's vault by issuer and type, the one whose subject is this community kept —
/// never another party's credential from the same room — and replaced.
#[tokio::test]
async fn an_older_rooms_credentials_are_found_in_the_vtas_vault() {
    let fix = fixture().await;
    let now = whole_now();
    let until = now + chrono::Duration::days(1);
    let room = seed_room(&fix, until).await;
    fix.vta.stored(
        "legacy-m",
        credential(&room, "MembershipCredential", TEST_VTC_DID, &rfc3339(until)),
    );
    fix.vta.stored(
        "legacy-a",
        credential(&room, "AuthorityCredential", TEST_VTC_DID, &rfc3339(until)),
    );
    let other = credential(
        &room,
        "AuthorityCredential",
        "did:example:member",
        &rfc3339(until),
    );
    fix.vta.stored("another-a", other.clone());

    assert_eq!(sweep(&fix, now).await.renewed, vec![room.clone()]);
    let new_until = now + chrono::Duration::days(365);
    assert_eq!(
        assert_one_each(&fix, &room, new_until),
        ("legacy-m".into(), "legacy-a".into())
    );
    assert_eq!(
        fix.vta
            .held(&room, "AuthorityCredential", "did:example:member"),
        vec![("another-a".to_string(), other)]
    );
    let rec = community_renewal::record(&fix.vtc.state.community_rooms, &room)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.membership_vault_id.as_deref(), Some("legacy-m"));
    assert_eq!(rec.authority_vault_id.as_deref(), Some("legacy-a"));
}

/// A lapsed authority is still renewed — the VTA holds the room's key, which is what
/// issues — and that is how such a room is recovered.
#[tokio::test]
async fn a_lapsed_authority_is_renewed() {
    let fix = fixture().await;
    let now = whole_now();
    let room = seed_room(&fix, now - chrono::Duration::days(2)).await;
    assert_eq!(sweep(&fix, now).await.renewed, vec![room.clone()]);
    assert_one_each(&fix, &room, now + chrono::Duration::days(365));
}

/// Community rooms off, or no link to a VTA: no pass does anything, and nothing is
/// recorded as failing.
#[tokio::test]
async fn nothing_is_renewed_while_off_or_unlinked() {
    let now = whole_now();
    let fix = fixture_with(None, true).await;
    seed_room(&fix, now + chrono::Duration::days(1)).await;
    assert_eq!(sweep(&fix, now).await, SweepReport::default());
    assert!(fix.vta.calls().is_empty());

    let fix = fixture_with(Some(config()), false).await;
    let room = seed_room(&fix, now + chrono::Duration::days(1)).await;
    assert_eq!(sweep(&fix, now).await, SweepReport::default());
    assert!(
        community_renewal::record(&fix.vtc.state.community_rooms, &room)
            .await
            .unwrap()
            .is_none()
    );
}
