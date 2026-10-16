//! Rooms the community owns (`docs/05-design-notes/data-rooms-files.md` §8.4):
//! `vtc/rooms/community/{create,list,get}/0.1`, `vtc/rooms/community/members/{add,remove,
//! list}/0.1` and `vtc/rooms/offers/{list,accept}/0.1`, driven through the signed-document
//! door as an administrator's and a member's clients do.
//!
//! The community's VTA is a stand-in that keeps a real room key: it signs the room's
//! membership and authority credentials as a real VTA would, so the credentials an offer
//! hands a member are ones this community, **as the room's host**, then honours — the
//! owner's record never consulted. What it does not do is run MLS: a Welcome is an opaque
//! token, which is all this community ever sees of one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dtg_credentials::{DTGCredential, IssuerScope};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use trust_tasks_rs::TrustTask;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, VtcRole};
use vtc_service::config::CommunityRoomsConfig;
use vtc_service::members::{Member, store_member};
use vtc_service::rooms::community::codes::*;
use vtc_service::rooms::vta_storage::{PeerError, VtaChannel};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::Gesturer;
use crate::common::signed::{error_code, post, seed_role, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const CREATE: &str = "https://trusttasks.org/spec/vtc/rooms/community/create/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/rooms/community/list/0.1";
const GET: &str = "https://trusttasks.org/spec/vtc/rooms/community/get/0.1";
const ADD: &str = "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.1";
const REMOVE: &str = "https://trusttasks.org/spec/vtc/rooms/community/members/remove/0.1";
const MEMBERS: &str = "https://trusttasks.org/spec/vtc/rooms/community/members/list/0.1";
const OFFERS: &str = "https://trusttasks.org/spec/vtc/rooms/offers/list/0.1";
const ACCEPT: &str = "https://trusttasks.org/spec/vtc/rooms/offers/accept/0.1";

const MINT: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.1";
const GROUP_CREATE: &str = "https://trusttasks.org/spec/rooms/owner/group/create/0.1";
const GROUP_ADD: &str = "https://trusttasks.org/spec/rooms/owner/group/add/0.2";
const GROUP_ADD_V0_1: &str = "https://trusttasks.org/spec/rooms/owner/group/add/0.1";
const GROUP_REMOVE: &str = "https://trusttasks.org/spec/rooms/owner/group/remove/0.1";
const INVITE: &str = "https://trusttasks.org/spec/rooms/owner/invite/0.1";
const ISSUE_MEMBERSHIP: &str = "https://trusttasks.org/spec/rooms/owner/issue-membership/0.1";
const ISSUE_AUTHORITY: &str = "https://trusttasks.org/spec/rooms/owner/issue-authority/0.2";
const RECEIVE: &str = "https://trusttasks.org/spec/vault/credentials/receive/0.1";

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

// ─── the community's VTA, standing in ───────────────────────────────────

/// What the stand-in does with the next request of a type.
#[derive(Clone)]
enum Script {
    /// No answer: the outcome is unknown.
    Silent,
    /// A refusal with this code.
    Refuse(&'static str),
    /// Serve the request — its effect happens — and then lose the answer.
    ServeThenSilent,
}

#[derive(Default)]
struct VtaState {
    /// Every request, in order: its type and payload.
    calls: Vec<(String, Value)>,
    /// The key of each room this VTA minted, by the room's DID.
    rooms: HashMap<String, Party>,
    /// Each sealed room's group: its members and its room epoch.
    groups: HashMap<String, (Vec<String>, u64)>,
    /// What to do with the next request of a type, instead of serving it.
    scripted: HashMap<String, Script>,
    /// Answer a serverless mint with this log.
    serverless_log: Option<String>,
    /// The last admission applied per room — member, KeyPackage, epoch, Welcome — as
    /// `rooms/owner/group/add/0.2` item 8 keeps it until the room's next advance.
    admitted: HashMap<String, (String, String, u64, String)>,
    /// A VTA that predates `rooms/owner/group/add/0.2`: it refuses it `unsupportedType`.
    add_0_1_only: bool,
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

    fn calls(&self) -> Vec<(String, Value)> {
        self.0.lock().unwrap().calls.clone()
    }

    fn types_called(&self) -> Vec<String> {
        self.calls().into_iter().map(|(t, _)| t).collect()
    }

    fn clear_calls(&self) {
        self.0.lock().unwrap().calls.clear();
    }

    fn room_key(&self, room: &str) -> Party {
        let st = self.0.lock().unwrap();
        let p = st.rooms.get(room).expect("a room this VTA minted");
        Party {
            did: p.did.clone(),
            secret_multibase: p.secret_multibase.clone(),
            secret: p.secret.clone(),
        }
    }

    fn group(&self, room: &str) -> Option<(Vec<String>, u64)> {
        self.0.lock().unwrap().groups.get(room).cloned()
    }

    async fn credential(room: &Party, kind: &str, subject: &str, payload: &Value) -> String {
        let now = Utc::now();
        let until = payload["validUntil"]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or(now + chrono::Duration::days(30));
        let mut c = match kind {
            "membership" => DTGCredential::new_vmc(
                room.did.clone(),
                subject.to_string(),
                now - chrono::Duration::minutes(1),
                Some(until),
                false,
            ),
            "authority" => DTGCredential::new_vac(
                room.did.clone(),
                IssuerScope::Public,
                subject.to_string(),
                room.did.clone(),
                payload["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_string())
                    .collect(),
                now - chrono::Duration::minutes(1),
                until,
            )
            .expect("a VAC"),
            _ => DTGCredential::new_vic(
                room.did.clone(),
                IssuerScope::Public,
                subject.to_string(),
                now - chrono::Duration::minutes(1),
                Some(until),
            ),
        };
        c.sign(&room.secret, None).await.expect("sign");
        serde_json::to_string(&c).unwrap()
    }

    async fn serve(&self, type_uri: &str, p: &Value) -> Result<Value, (&'static str, String)> {
        match type_uri {
            MINT => {
                let room = Party::new();
                let did = room.did.clone();
                let mut st = self.0.lock().unwrap();
                st.rooms.insert(did.clone(), room);
                let mut answer = json!({
                    "did": did,
                    "contextId": p["contextId"],
                    "scid": "QmScid",
                    "portable": true,
                    "signingKeyId": format!("{did}#key-1"),
                    "kaKeyId": format!("{did}#key-2"),
                    "preRotationKeyCount": 0,
                    "createdAt": Utc::now().to_rfc3339(),
                });
                match &st.serverless_log {
                    Some(log) if p.get("url").is_some() => {
                        answer["serverless"] = json!(true);
                        answer["logEntry"] = json!(log);
                    }
                    _ => answer["serverId"] = p["serverId"].clone(),
                }
                Ok(answer)
            }
            GROUP_CREATE => {
                let room = p["roomId"].as_str().unwrap().to_string();
                let member = p["member"].as_str().unwrap().to_string();
                self.0
                    .lock()
                    .unwrap()
                    .groups
                    .insert(room.clone(), (vec![member], 1));
                Ok(json!({ "roomId": room, "epoch": 1 }))
            }
            ISSUE_MEMBERSHIP | ISSUE_AUTHORITY | INVITE => {
                let room = self.room_key(p["roomId"].as_str().unwrap());
                let subject = p["subject"].as_str().unwrap();
                let kind = match type_uri {
                    ISSUE_MEMBERSHIP => "membership",
                    ISSUE_AUTHORITY => "authority",
                    _ => "invitation",
                };
                let credential = Self::credential(&room, kind, subject, p).await;
                Ok(json!({
                    "credential": credential,
                    "credentialId": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                }))
            }
            RECEIVE => Ok(json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "types": ["VerifiableCredential"],
                "status": "valid",
            })),
            GROUP_ADD | GROUP_ADD_V0_1 => {
                let room = p["roomId"].as_str().unwrap().to_string();
                let member = p["member"].as_str().unwrap().to_string();
                let key_package = p["keyPackage"].as_str().unwrap_or_default().to_string();
                let mut st = self.0.lock().unwrap();
                if type_uri == GROUP_ADD && st.add_0_1_only {
                    return Err(("unsupportedType", format!("{type_uri} is not served here")));
                }
                if key_package == "bm90LWEta2V5LXBhY2thZ2U" {
                    return Err((
                        "rooms/owner/group/add:keyPackageInvalid",
                        "the KeyPackage cannot admit the member".into(),
                    ));
                }
                let kept = st.admitted.get(&room).cloned();
                let group = st.groups.get_mut(&room).expect("a group");
                if group.0.contains(&member) {
                    // 0.2 item 8: the identical request is answered with the kept Welcome.
                    return match kept {
                        Some((m, kp, epoch, welcome))
                            if type_uri == GROUP_ADD && m == member && kp == key_package =>
                        {
                            Ok(json!({
                                "roomId": room, "member": member, "epoch": epoch,
                                "welcome": welcome,
                            }))
                        }
                        _ => Err((
                            "rooms/owner/group/add:alreadyMember",
                            "already has a leaf".into(),
                        )),
                    };
                }
                group.0.push(member.clone());
                group.1 += 1;
                let (epoch, welcome) = (group.1, format!("V2VsY29tZQ-{}", group.1));
                st.admitted.insert(
                    room.clone(),
                    (member.clone(), key_package, epoch, welcome.clone()),
                );
                Ok(json!({
                    "roomId": room,
                    "member": member,
                    "epoch": epoch,
                    "welcome": welcome,
                }))
            }
            GROUP_REMOVE => {
                let room = p["roomId"].as_str().unwrap().to_string();
                let member = p["member"].as_str().unwrap().to_string();
                let mut st = self.0.lock().unwrap();
                let group = st.groups.get_mut(&room).expect("a group");
                let Some(at) = group.0.iter().position(|m| *m == member) else {
                    return Err(("rooms/owner/group/remove:notMember", "no leaf".into()));
                };
                group.0.remove(at);
                // The next advance ends the kept admission (add 0.2 item 8).
                st.admitted.remove(&room);
                let group = st.groups.get_mut(&room).expect("a group");
                group.1 += 1;
                Ok(json!({ "roomId": room, "member": member, "epoch": group.1 }))
            }
            other => Err(("unsupportedType", format!("{other} is not served here"))),
        }
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
        _timeout: Duration,
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
            Some(Script::ServeThenSilent) => {
                let _ = self.serve(type_uri, payload).await;
                return Err(PeerError::Transient("the answer was lost".into()));
            }
            None => {}
        }
        Ok(match self.serve(type_uri, payload).await {
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
    gesturer: Gesturer,
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

async fn fixture_with(
    community: Option<CommunityRoomsConfig>,
    with_vta: bool,
    serverless_log: Option<&str>,
) -> Fixture {
    let vta = FakeVta::default();
    vta.0.lock().unwrap().serverless_log = serverless_log.map(str::to_string);
    let mut builder = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url(RP_ORIGIN)
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
    let mut gesturer = Gesturer::new();
    let admin = crate::common::signed::admin(&vtc).await;
    gesturer.enrol(&vtc, &admin.did).await;
    Fixture {
        vtc,
        vta,
        gesturer,
        admin,
    }
}

async fn fixture() -> Fixture {
    fixture_with(Some(config()), true, None).await
}

/// An active member of the community: an ACL entry of role `member` and a member record.
async fn member(fix: &Fixture) -> Party {
    let p = Party::new();
    seed_role(&fix.vtc, &p.did, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&p.did))
        .await
        .unwrap();
    p
}

/// Send as the administrator, through the step-up the change asks for.
async fn admin_call(fix: &mut Fixture, uri: &str, payload: Value) -> (StatusCode, Value) {
    let doc = signed(&fix.admin, uri, payload).await;
    let admin = Party {
        did: fix.admin.did.clone(),
        secret_multibase: fix.admin.secret_multibase.clone(),
        secret: fix.admin.secret.clone(),
    };
    let (status, reply) = fix.gesturer.send_through(&fix.vtc, &admin, &[], &doc).await;
    if reply["type"].as_str() == Some(format!("{uri}#response").as_str()) {
        crate::common::signed::assert_conforms(uri, &reply);
    }
    (status, reply)
}

/// Send as `who`, with no step-up.
async fn call_as(fix: &Fixture, who: &Party, uri: &str, payload: Value) -> Value {
    let (_, reply) = post(&fix.vtc, &signed(who, uri, payload).await).await;
    if reply["type"].as_str() == Some(format!("{uri}#response").as_str()) {
        crate::common::signed::assert_conforms(uri, &reply);
    }
    reply
}

async fn create_room(fix: &mut Fixture, visibility: &str) -> String {
    let (status, reply) = admin_call(
        fix,
        CREATE,
        json!({ "label": "Board pack", "visibility": visibility, "reason": "the board's papers" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["payload"]["room"]["room"]["roomId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn add_member(fix: &mut Fixture, room: &str, member: &str, valid_until: &str) -> Value {
    admin_call(
        fix,
        ADD,
        json!({
            "roomId": room, "member": member, "actions": ["read", "write"],
            "validUntil": valid_until, "reason": "joins the board",
        }),
    )
    .await
    .1
}

fn in_a_year() -> String {
    (Utc::now() + chrono::Duration::days(365)).to_rfc3339()
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

// ─── end to end ─────────────────────────────────────────────────────────

/// The whole of an open room's life: the community's VTA mints and equips it, the room is
/// stored as the community's own, a member is offered admission and accepts, and the
/// credentials the offer handed them are what this community, as the room's **host**,
/// honours for a write and a read — the owner's record never consulted. Then they are
/// removed, and told what removal does not do.
#[tokio::test]
async fn an_open_community_room_from_creation_to_use_to_removal() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "open").await;

    // Steps 1–3 at the VTA, in order; an open room has no group.
    assert_eq!(
        fix.vta.types_called(),
        vec![MINT, ISSUE_MEMBERSHIP, RECEIVE, ISSUE_AUTHORITY, RECEIVE],
    );
    let calls = fix.vta.calls();
    assert_eq!(calls[0].1["template"], "room");
    assert_eq!(calls[0].1["setPrimary"], false);
    assert_eq!(calls[0].1["contextId"], "vtc");
    assert_eq!(calls[0].1["serverId"], "hosting");
    // The community's own credentials name the community, admin included, and are kept
    // in its VTA's vault, in the configured context.
    assert_eq!(calls[1].1["subject"], TEST_VTC_DID);
    assert_eq!(calls[3].1["subject"], TEST_VTC_DID);
    assert_eq!(
        calls[3].1["actions"],
        json!(["read", "write", "curate", "admin"])
    );
    assert_eq!(calls[2].1["contextId"], "vtc");

    // Hosted here, owned by the community.
    let hosted = vti_rooms::storage::get_room(&fix.vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    assert_eq!(hosted.owner_did, TEST_VTC_DID);
    let got = call_as(&fix, &fix.admin, GET, json!({ "roomId": room })).await;
    assert_eq!(got["payload"]["room"]["label"], "Board pack");
    assert_eq!(got["payload"]["room"]["room"]["ownerDid"], TEST_VTC_DID);
    let listed = call_as(&fix, &fix.admin, LIST, json!({})).await;
    assert_eq!(listed["payload"]["items"].as_array().unwrap().len(), 1);

    // Offered.
    let alice = member(&fix).await;
    fix.vta.clear_calls();
    let added = add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    assert_eq!(added["payload"]["member"]["state"], "offered", "{added}");
    assert!(
        added["payload"].get("credentials").is_none(),
        "the credentials are kept for the member, never returned to the administrator"
    );
    assert_eq!(
        fix.vta.types_called(),
        vec![INVITE, ISSUE_MEMBERSHIP, ISSUE_AUTHORITY]
    );
    assert_eq!(fix.vta.calls()[2].1["actions"], json!(["read", "write"]));
    let got = call_as(&fix, &fix.admin, GET, json!({ "roomId": room })).await;
    assert_eq!(got["payload"]["room"]["offered"], 1);

    // The member sees their offer, and nobody else does.
    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    let offer = &offers["payload"]["items"][0];
    assert_eq!(offer["roomId"], room, "{offers}");
    assert_eq!(offer["state"], "open");
    assert_eq!(offer["host"], TEST_VTC_DID);
    let bob = member(&fix).await;
    let none = call_as(&fix, &bob, OFFERS, json!({})).await;
    assert_eq!(none["payload"]["items"], json!([]), "{none}");

    // Accepted: an open room has no group, so nothing goes to the VTA.
    fix.vta.clear_calls();
    let accepted = call_as(&fix, &alice, ACCEPT, json!({ "roomId": room })).await;
    assert_eq!(accepted["payload"]["state"], "admitted", "{accepted}");
    assert!(accepted["payload"].get("welcome").is_none());
    assert!(fix.vta.calls().is_empty());

    // The host honours the room's credentials and nothing else.
    let presentation = json!({
        "membership": offer["credentials"]["membership"],
        "authority": [offer["credentials"]["authority"]],
    });
    let put = call_as(
        &fix,
        &alice,
        vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
        json!({
            "roomId": room, "key": "minutes", "presentation": presentation,
            "cleartext": { "body": "the board met" },
        }),
    )
    .await;
    assert_eq!(put["payload"]["version"], 1, "{put}");
    let read = call_as(
        &fix,
        &alice,
        vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
        json!({ "roomId": room, "key": "minutes", "presentation": presentation }),
    )
    .await;
    assert_eq!(read["payload"]["cleartext"]["body"], "the board met");
    assert_eq!(read["payload"]["author"], alice.did);

    // Removed: no group to advance on an open room, and the answer says what removal
    // does not do.
    let (_, removed) = admin_call(
        &mut fix,
        REMOVE,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(
        removed["payload"]["member"]["state"], "removed",
        "{removed}"
    );
    assert!(removed["payload"].get("epoch").is_none());
    assert!(
        removed["payload"]["ext"]["org.openvtc"]["notice"]
            .as_str()
            .unwrap()
            .contains("recalls nothing")
    );
    let members = call_as(&fix, &fix.admin, MEMBERS, json!({ "roomId": room })).await;
    assert_eq!(members["payload"]["items"][0]["state"], "removed");
    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    assert_eq!(
        offers["payload"]["items"],
        json!([]),
        "a removed member has no offer"
    );

    let audit = audit_rows(&fix).await;
    for event in [
        "created",
        "memberOffered",
        "memberAdmitted",
        "memberRemoved",
    ] {
        assert!(audit.contains(event), "{event} is audited");
    }
    assert!(
        !audit.contains("V2VsY29tZQ") && !audit.contains("\"credential\""),
        "no Welcome and no credential reaches the audit trail"
    );
}

/// A sealed room: the VTA founds the group with the community as its only member, admits
/// the member's KeyPackage advancing the room at this community as its host, a repeat
/// with the same KeyPackage gets the same Welcome, and removal advances the room past
/// the member.
#[tokio::test]
async fn a_sealed_community_room_admits_and_removes_through_the_vta() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    assert_eq!(
        fix.vta.types_called(),
        vec![
            MINT,
            GROUP_CREATE,
            ISSUE_MEMBERSHIP,
            RECEIVE,
            ISSUE_AUTHORITY,
            RECEIVE
        ],
    );
    assert_eq!(fix.vta.calls()[1].1["member"], TEST_VTC_DID);

    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    fix.vta.clear_calls();
    let accepted = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(accepted["payload"]["epoch"], 2, "{accepted}");
    let welcome = accepted["payload"]["welcome"].clone();
    assert!(welcome.is_string());
    let calls = fix.vta.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, GROUP_ADD);
    assert_eq!(
        calls[0].1["host"], TEST_VTC_DID,
        "this community is the room's host"
    );
    assert_eq!(
        calls[0].1["member"], alice.did,
        "the proven signer, never a payload field"
    );

    // A lost answer: the same KeyPackage again is the same Welcome, and nothing moves.
    fix.vta.clear_calls();
    let again = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(again["payload"]["welcome"], welcome);
    assert_eq!(again["payload"]["epoch"], 2);
    assert!(fix.vta.calls().is_empty());
    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    assert_eq!(offers["payload"]["items"][0]["state"], "accepted");

    // A different KeyPackage is not what was offered.
    let other = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1B" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&other),
        Some(ACCEPT_ALREADY_ACCEPTED),
        "{other}"
    );

    let (_, removed) = admin_call(
        &mut fix,
        REMOVE,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(removed["payload"]["epoch"], 3, "{removed}");
    let (members, epoch) = fix.vta.group(&room).unwrap();
    assert_eq!(members, vec![TEST_VTC_DID.to_string()]);
    assert_eq!(epoch, 3);
    let remove_call = fix
        .vta
        .calls()
        .into_iter()
        .find(|(t, _)| t == GROUP_REMOVE)
        .unwrap();
    assert_eq!(remove_call.1["host"], TEST_VTC_DID);
}

/// `rooms/owner/group/add/0.2` item 8, end to end: the VTA admitted the member and its
/// answer was lost, so the acceptance is `admissionPending` and nothing is recorded here.
/// The member's identical retry reaches the VTA again, which answers with the Welcome it
/// kept — the room does not advance a second time — and the acceptance completes.
#[tokio::test]
async fn an_acceptance_whose_vta_answer_was_lost_gets_the_welcome_on_retry() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;

    fix.vta.script(GROUP_ADD, Script::ServeThenSilent);
    let lost = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&lost),
        Some(ACCEPT_ADMISSION_PENDING),
        "{lost}"
    );
    assert_eq!(fix.vta.group(&room).unwrap().1, 2, "the VTA did admit them");

    fix.vta.clear_calls();
    let again = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(again["payload"]["state"], "admitted", "{again}");
    assert_eq!(again["payload"]["epoch"], 2, "{again}");
    assert_eq!(again["payload"]["welcome"], "V2VsY29tZQ-2", "{again}");
    assert_eq!(fix.vta.types_called(), vec![GROUP_ADD]);
    assert_eq!(
        fix.vta.group(&room).unwrap().1,
        2,
        "the room did not advance again"
    );
    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    assert_eq!(offers["payload"]["items"][0]["state"], "accepted");
}

/// A VTA that predates `rooms/owner/group/add/0.2` is asked at 0.1 — the same request —
/// and admits as before. Against it a lost answer is still `alreadyAccepted`: 0.1 keeps no
/// Welcome to answer a repeat with.
#[tokio::test]
async fn an_acceptance_falls_back_to_group_add_0_1() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    fix.vta.0.lock().unwrap().add_0_1_only = true;
    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;

    fix.vta.clear_calls();
    let accepted = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(accepted["payload"]["epoch"], 2, "{accepted}");
    assert_eq!(fix.vta.types_called(), vec![GROUP_ADD, GROUP_ADD_V0_1]);

    let bob = member(&fix).await;
    add_member(&mut fix, &room, &bob.did, &in_a_year()).await;
    fix.vta.script(GROUP_ADD_V0_1, Script::ServeThenSilent);
    let lost = call_as(
        &fix,
        &bob,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1B" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&lost),
        Some(ACCEPT_ADMISSION_PENDING),
        "{lost}"
    );
    let again = call_as(
        &fix,
        &bob,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1B" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&again),
        Some(ACCEPT_ALREADY_ACCEPTED),
        "{again}"
    );
}

/// A room identity minted serverless is served here, at the path the VTA minted it for.
#[tokio::test]
async fn a_served_room_identity_resolves_from_this_community() {
    let mut c = config();
    c.webvh_server = None;
    let mut fix = fixture_with(Some(c), true, Some("{\"versionId\":\"1-Qm\"}")).await;
    let room = create_room(&mut fix, "open").await;
    let url = fix.vta.calls()[0].1["url"].as_str().unwrap().to_string();
    let path = url.strip_prefix(RP_ORIGIN).expect("under the public URL");
    assert!(
        path.starts_with("/room-dids/") && path.ends_with("/did.jsonl"),
        "{path}"
    );
    let res = fix
        .vtc
        .router
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"{\"versionId\":\"1-Qm\"}");
    assert!(!room.is_empty());
}

// ─── refusals ───────────────────────────────────────────────────────────

/// Every declared refusal of a create, and that none leaves a room behind.
#[tokio::test]
async fn vtc_rooms_community_create_refuses_with_its_declared_codes() {
    let create = |v: &str| json!({ "label": "Board pack", "visibility": v, "reason": "r" });

    // No `[rooms.community]`: off, and the refusal says what to add.
    let mut off = fixture_with(None, true, None).await;
    let (_, r) = admin_call(&mut off, CREATE, create("open")).await;
    assert_eq!(tt_error_code(&r), Some(CREATE_NO_KEY_HOLDER), "{r}");
    assert!(
        r["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("[rooms.community]")
    );
    let listed = call_as(&off, &off.admin, LIST, json!({})).await;
    assert_eq!(
        listed["payload"]["ext"]["org.openvtc"]["communityRooms"]["enabled"], false,
        "the console reads what to add from the listing"
    );
    // No VTA to hold the keys: never a key held here instead.
    let mut unlinked = fixture_with(Some(config()), false, None).await;
    let (_, r) = admin_call(&mut unlinked, CREATE, create("open")).await;
    assert_eq!(tt_error_code(&r), Some(CREATE_NO_KEY_HOLDER), "{r}");

    let mut fix = fixture().await;
    // The shipped rooms policy has not enabled private rooms.
    let (_, r) = admin_call(&mut fix, CREATE, create("private")).await;
    assert_eq!(
        tt_error_code(&r),
        Some(CREATE_VISIBILITY_NOT_PERMITTED),
        "{r}"
    );
    let mut with_config = create("open");
    with_config["storageConfig"] = json!("nowhere");
    let (_, r) = admin_call(&mut fix, CREATE, with_config).await;
    assert_eq!(
        tt_error_code(&r),
        Some(CREATE_UNKNOWN_STORAGE_CONFIG),
        "{r}"
    );
    assert!(fix.vta.calls().is_empty(), "nothing reached the VTA");

    fix.vta.script(MINT, Script::Refuse("permissionDenied"));
    let (_, r) = admin_call(&mut fix, CREATE, create("open")).await;
    assert_eq!(tt_error_code(&r), Some(CREATE_KEY_HOLDER_REFUSED), "{r}");
    assert_eq!(r["payload"]["details"]["code"], "permissionDenied");

    // The VTA minted, then fell silent: nothing stored, and the DID it minted named.
    fix.vta.script(GROUP_CREATE, Script::Silent);
    let (_, r) = admin_call(&mut fix, CREATE, create("attributed")).await;
    assert_eq!(
        tt_error_code(&r),
        Some(CREATE_KEY_HOLDER_UNAVAILABLE),
        "{r}"
    );
    let minted = r["payload"]["details"]["roomId"].as_str().unwrap();
    assert!(minted.starts_with("did:key:"));
    assert!(
        vti_rooms::storage::get_room(&fix.vtc.state.rooms_ks, minted)
            .await
            .is_err(),
        "no room exists at its host without a key holder behind it"
    );
    let listed = call_as(&fix, &fix.admin, LIST, json!({})).await;
    assert_eq!(listed["payload"]["items"], json!([]));
}

/// The owner's reads: a room the community only hosts is `notFound` too.
#[tokio::test]
async fn vtc_rooms_community_reads_answer_not_found() {
    let mut fix = fixture().await;
    let r = call_as(
        &fix,
        &fix.admin,
        GET,
        json!({ "roomId": "did:key:z6MkNobody" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(GET_NOT_FOUND), "{r}");
    let r = call_as(
        &fix,
        &fix.admin,
        MEMBERS,
        json!({ "roomId": "did:key:z6MkNobody" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(MEMBERS_LIST_NOT_FOUND), "{r}");

    // Hosted, owned by a member: not the community's.
    let hosted = vti_rooms::Room {
        room_id: "did:key:z6MkMembersRoom".into(),
        owner_did: "did:key:z6MkAMember".into(),
        visibility: vti_rooms::Visibility::Open,
        retention_policy: vti_rooms::RetentionPolicy::Chained,
        anchor_cadence: Default::default(),
        epoch: 1,
        next_version: 1,
        retention_days: 90,
        epoch_expires_at: None,
        created_at: 0,
        updated_at: 0,
        mirror_of: None,
    };
    vti_rooms::storage::create_room(&fix.vtc.state.rooms_ks, &hosted)
        .await
        .unwrap();
    let r = call_as(&fix, &fix.admin, GET, json!({ "roomId": hosted.room_id })).await;
    assert_eq!(tt_error_code(&r), Some(GET_NOT_FOUND), "{r}");

    // A caller without `vtc.rooms.manage` is refused before anything is read.
    let narrow = Party::new();
    let row = vtc_service::acl::VtcAclEntry {
        did: narrow.did.clone(),
        role: VtcRole::Admin,
        label: None,
        // Hosting's authority, and not the owner's.
        admin: {
            let mut a = AdminAuthority::community_admin();
            a.capabilities = vtc_service::acl::CapabilityScope::listed(vec![
                vtc_service::acl::CapabilityGrant::from(
                    "vtc.rooms.admin"
                        .parse::<vtc_service::acl::CapRef>()
                        .unwrap(),
                ),
            ])
            .unwrap();
            a
        },
        delegated_by: None,
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
        resource_grants: Vec::new(),
        label_set_by_subject: false,
        suspension: None,
    };
    vtc_service::acl::store_acl_entry(&fix.vtc.state.acl_ks, &row)
        .await
        .unwrap();
    let r = call_as(&fix, &narrow, LIST, json!({})).await;
    assert_eq!(tt_error_code(&r), Some("permissionDenied"), "{r}");
    let room = create_room(&mut fix, "open").await;
    let r = call_as(&fix, &narrow, GET, json!({ "roomId": room })).await;
    assert_eq!(tt_error_code(&r), Some("permissionDenied"), "{r}");
}

/// Every declared refusal of `members/add` and `members/remove`.
#[tokio::test]
async fn vtc_rooms_community_members_refuse_with_their_declared_codes() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    let alice = member(&fix).await;
    let stranger = Party::new();

    let r = add_member(&mut fix, "did:key:z6MkNobody", &alice.did, &in_a_year()).await;
    assert_eq!(tt_error_code(&r), Some(ADD_NOT_FOUND), "{r}");
    let r = add_member(&mut fix, &room, &stranger.did, &in_a_year()).await;
    assert_eq!(tt_error_code(&r), Some(ADD_NOT_A_MEMBER), "{r}");
    fix.vta.script(INVITE, Script::Silent);
    let r = add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    assert_eq!(tt_error_code(&r), Some(ADD_KEY_HOLDER_UNAVAILABLE), "{r}");
    fix.vta
        .script(ISSUE_AUTHORITY, Script::Refuse("permissionDenied"));
    let r = add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    assert_eq!(tt_error_code(&r), Some(ADD_KEY_HOLDER_REFUSED), "{r}");
    assert_eq!(r["payload"]["details"]["code"], "permissionDenied");
    // Nothing was offered by either.
    let members = call_as(&fix, &fix.admin, MEMBERS, json!({ "roomId": room })).await;
    assert_eq!(members["payload"]["items"], json!([]), "{members}");

    let r = add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    assert_eq!(r["payload"]["member"]["state"], "offered", "{r}");
    let r = add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    assert_eq!(tt_error_code(&r), Some(ADD_ALREADY_MEMBER), "{r}");

    let remove = |room: &str, who: &str| json!({ "roomId": room, "member": who, "reason": "r" });
    let (_, r) = admin_call(&mut fix, REMOVE, remove("did:key:z6MkNobody", &alice.did)).await;
    assert_eq!(tt_error_code(&r), Some(REMOVE_NOT_FOUND), "{r}");
    let (_, r) = admin_call(&mut fix, REMOVE, remove(&room, &stranger.did)).await;
    assert_eq!(tt_error_code(&r), Some(REMOVE_NOT_IN_ROOM), "{r}");

    // Admitted, then the VTA cannot advance the room: nothing changes here.
    let accepted = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(accepted["payload"]["state"], "admitted", "{accepted}");
    fix.vta.script(GROUP_REMOVE, Script::Silent);
    let (_, r) = admin_call(&mut fix, REMOVE, remove(&room, &alice.did)).await;
    assert_eq!(
        tt_error_code(&r),
        Some(REMOVE_KEY_HOLDER_UNAVAILABLE),
        "{r}"
    );
    fix.vta.script(
        GROUP_REMOVE,
        Script::Refuse("rooms/owner/group/remove:noAuthority"),
    );
    let (_, r) = admin_call(&mut fix, REMOVE, remove(&room, &alice.did)).await;
    assert_eq!(tt_error_code(&r), Some(REMOVE_KEY_HOLDER_REFUSED), "{r}");
    let members = call_as(
        &fix,
        &fix.admin,
        MEMBERS,
        json!({ "roomId": room, "state": "admitted" }),
    )
    .await;
    assert_eq!(
        members["payload"]["items"][0]["member"], alice.did,
        "{members}"
    );

    // An open offer is withdrawn without the VTA.
    let bob = member(&fix).await;
    add_member(&mut fix, &room, &bob.did, &in_a_year()).await;
    fix.vta.clear_calls();
    let (_, r) = admin_call(&mut fix, REMOVE, remove(&room, &bob.did)).await;
    assert_eq!(r["payload"]["member"]["state"], "removed", "{r}");
    assert!(fix.vta.calls().is_empty());
    let accept = call_as(
        &fix,
        &bob,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&accept),
        Some(ACCEPT_NOT_FOUND),
        "a withdrawn offer is never accepted"
    );
}

/// Every declared refusal of the member's half.
#[tokio::test]
async fn vtc_rooms_offers_refuse_with_their_declared_codes() {
    let mut fix = fixture().await;
    let sealed = create_room(&mut fix, "attributed").await;
    let open = create_room(&mut fix, "open").await;
    let alice = member(&fix).await;
    let stranger = Party::new();

    let r = call_as(&fix, &stranger, OFFERS, json!({})).await;
    assert_eq!(tt_error_code(&r), Some(OFFERS_LIST_NOT_A_MEMBER), "{r}");
    let r = call_as(&fix, &stranger, ACCEPT, json!({ "roomId": open })).await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_NOT_A_MEMBER), "{r}");
    let r = call_as(&fix, &alice, ACCEPT, json!({ "roomId": open })).await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_NOT_FOUND), "{r}");

    add_member(&mut fix, &open, &alice.did, &in_a_year()).await;
    let r = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": open, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&r),
        Some(ACCEPT_KEY_PACKAGE_NOT_EXPECTED),
        "{r}"
    );

    add_member(&mut fix, &sealed, &alice.did, &in_a_year()).await;
    let r = call_as(&fix, &alice, ACCEPT, json!({ "roomId": sealed })).await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_KEY_PACKAGE_REQUIRED), "{r}");
    let r = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "bm90LWEta2V5LXBhY2thZ2U" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_KEY_PACKAGE_INVALID), "{r}");
    fix.vta.script(GROUP_ADD, Script::Silent);
    let r = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_ADMISSION_PENDING), "{r}");
    fix.vta.script(
        GROUP_ADD,
        Script::Refuse("rooms/owner/group/add:noAuthority"),
    );
    let r = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_KEY_HOLDER_REFUSED), "{r}");
    assert_eq!(
        r["payload"]["details"]["code"],
        "rooms/owner/group/add:noAuthority"
    );
    // Neither left an admission behind.
    let members = call_as(
        &fix,
        &fix.admin,
        MEMBERS,
        json!({ "roomId": sealed, "state": "admitted" }),
    )
    .await;
    assert_eq!(members["payload"]["items"], json!([]));

    // The VTA had in fact admitted them, and no Welcome is kept anywhere — here, or at the
    // VTA (not this admission's, which the VTA never applied as a repeatable one): the
    // member is in the group with no way in.
    fix.vta
        .0
        .lock()
        .unwrap()
        .groups
        .get_mut(&sealed)
        .unwrap()
        .0
        .push(alice.did.clone());
    let r = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_ALREADY_ACCEPTED), "{r}");

    // An offer past its expiry.
    let bob = member(&fix).await;
    let soon = (Utc::now() + chrono::Duration::seconds(1)).to_rfc3339();
    add_member(&mut fix, &open, &bob.did, &soon).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let r = call_as(&fix, &bob, ACCEPT, json!({ "roomId": open })).await;
    assert_eq!(tt_error_code(&r), Some(ACCEPT_OFFER_EXPIRED), "{r}");
}
