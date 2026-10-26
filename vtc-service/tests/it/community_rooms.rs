//! Rooms the community owns (`docs/05-design-notes/data-rooms-files.md` §8.4):
//! `vtc/rooms/community/{create,list,get}/{0.1,0.2}`, `vtc/rooms/community/update/0.1`,
//! `vtc/rooms/community/members/{add,remove,list}/0.1` and `vtc/rooms/offers/list/{0.1,0.2}`
//! and `vtc/rooms/offers/accept/0.1`, driven through the signed-document door as an
//! administrator's and a member's clients do.
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
const CREATE_V0_2: &str = "https://trusttasks.org/spec/vtc/rooms/community/create/0.2";
const LIST_V0_2: &str = "https://trusttasks.org/spec/vtc/rooms/community/list/0.2";
const GET_V0_2: &str = "https://trusttasks.org/spec/vtc/rooms/community/get/0.2";
const UPDATE: &str = "https://trusttasks.org/spec/vtc/rooms/community/update/0.1";
const OFFERS_V0_2: &str = "https://trusttasks.org/spec/vtc/rooms/offers/list/0.2";
const ACCEPT: &str = "https://trusttasks.org/spec/vtc/rooms/offers/accept/0.1";
const MEMBERSHIPS: &str = "https://trusttasks.org/spec/vtc/rooms/memberships/list/0.1";

const MINT: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.1";
const GROUP_CREATE: &str = "https://trusttasks.org/spec/rooms/owner/group/create/0.1";
const GROUP_ADD: &str = "https://trusttasks.org/spec/rooms/owner/group/add/0.3";
const GROUP_REMOVE: &str = "https://trusttasks.org/spec/rooms/owner/group/remove/0.1";
const GROUP_REMOVE_V0_3: &str = "https://trusttasks.org/spec/rooms/owner/group/remove/0.3";
const OWNER_REVOKE: &str = "https://trusttasks.org/spec/rooms/owner/revoke/0.1";
const REMOVE_V0_2: &str = "https://trusttasks.org/spec/vtc/rooms/community/members/remove/0.2";
const INVITE: &str = "https://trusttasks.org/spec/rooms/owner/invite/0.1";
const ISSUE_MEMBERSHIP: &str = "https://trusttasks.org/spec/rooms/owner/issue-membership/0.1";
const ISSUE_AUTHORITY: &str = "https://trusttasks.org/spec/rooms/owner/issue-authority/0.2";
const RECEIVE: &str = "https://trusttasks.org/spec/vault/credentials/receive/0.1";
const CREATE_V0_3: &str = "https://trusttasks.org/spec/vtc/rooms/community/create/0.3";
const UPDATE_V0_2: &str = "https://trusttasks.org/spec/vtc/rooms/community/update/0.2";
const PROFILE_READ: &str = "https://trusttasks.org/spec/rooms/keys/profile/read/0.1";
const PROFILE_WRITE: &str = "https://trusttasks.org/spec/rooms/keys/profile/write/0.1";

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
    /// `rooms/owner/group/add/0.3` item 8 keeps it until the room's next advance.
    admitted: HashMap<String, (String, String, u64, String)>,
    /// Each room's profile as the stand-in holds it — what `rooms/keys/profile/write`
    /// last wrote, or what a test set as a curator's edit in the room.
    profiles: HashMap<String, Value>,
    /// The community's revocation keyspace — where a list this VTA signs lands, standing in
    /// for its `rooms/revocations/put` to the community as the room's host.
    host: Option<vti_common::store::KeyspaceHandle>,
    /// Issue credentials valid from now rather than a minute ago — as the VTA does — so a
    /// test can tell what was issued after a withdrawal from what was issued before it.
    issue_from_now: bool,
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

    async fn credential(
        room: &Party,
        kind: &str,
        subject: &str,
        payload: &Value,
        from_now: bool,
    ) -> String {
        let now = Utc::now();
        let from = if from_now {
            now
        } else {
            now - chrono::Duration::minutes(1)
        };
        let until = payload["validUntil"]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or(now + chrono::Duration::days(30));
        let mut c = match kind {
            "membership" => DTGCredential::new_vmc(
                room.did.clone(),
                subject.to_string(),
                from,
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
                from,
                until,
            )
            .expect("a VAC"),
            _ => DTGCredential::new_vic(
                room.did.clone(),
                IssuerScope::Public,
                subject.to_string(),
                from,
                Some(until),
            ),
        };
        c.sign(&room.secret, None).await.expect("sign");
        serde_json::to_string(&c).unwrap()
    }

    fn profile(&self, room: &str) -> Option<Value> {
        self.0.lock().unwrap().profiles.get(room).cloned()
    }

    fn set_profile(&self, room: &str, profile: Value) {
        self.0
            .lock()
            .unwrap()
            .profiles
            .insert(room.to_string(), profile);
    }

    /// Sign the room's next list withdrawing `subject`, as the room, and put it in force at
    /// the community (the room's host). Returns the list, its head and the `revokedAt`.
    async fn withdraw(&self, room_id: &str, subject: &str) -> (Value, Value, String) {
        use vti_rooms::revocation::{Entry, HeldList, RevocationList, held, next_unsigned, store};
        let room = self.room_key(room_id);
        let host = self
            .0
            .lock()
            .unwrap()
            .host
            .clone()
            .expect("a host keyspace");
        let current = held(&host, room_id)
            .await
            .unwrap()
            .map(|h| RevocationList::parse(&h.list, room_id).unwrap());
        let now = Utc::now();
        let unsigned = next_unsigned(
            room_id,
            current.as_ref(),
            &[Entry::Subject {
                subject: subject.to_string(),
                revoked_at: now,
                until: None,
            }],
            now,
        );
        let list = vti_rooms_dtg::test_support::sign_as(&room, unsigned).await;
        store(
            &host,
            room_id,
            &HeldList {
                list: list.clone(),
                in_force_at: now,
            },
        )
        .await
        .unwrap();
        let head = RevocationList::parse(&list, room_id)
            .unwrap()
            .head()
            .to_wire();
        (list, head, vti_rooms::revocation::rfc3339(now))
    }

    async fn serve(&self, type_uri: &str, p: &Value) -> Result<Value, (&'static str, String)> {
        match type_uri {
            OWNER_REVOKE => {
                let room = p["roomId"].as_str().unwrap();
                let subject = p["withdraw"][0]["subject"].as_str().unwrap();
                let (list, head, _) = self.withdraw(room, subject).await;
                Ok(json!({
                    "roomId": room, "list": list, "head": head,
                    "deliveries": [{
                        "host": p["hosts"][0], "outcome": "accepted", "head": head,
                        "inForceAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    }],
                }))
            }
            GROUP_REMOVE_V0_3 => {
                let room = p["roomId"].as_str().unwrap().to_string();
                let member = p["member"].as_str().unwrap().to_string();
                if !self.group(&room).is_some_and(|(m, _)| m.contains(&member)) {
                    return Err(("rooms/owner/group/remove:notMember", "no leaf".into()));
                }
                // Withdraw first, then advance.
                let (_, head, revoked_at) = self.withdraw(&room, &member).await;
                let mut st = self.0.lock().unwrap();
                st.admitted.remove(&room);
                let group = st.groups.get_mut(&room).expect("a group");
                group.0.retain(|m| *m != member);
                group.1 += 1;
                Ok(json!({
                    "roomId": room, "member": member, "revocation": head,
                    "revokedAt": revoked_at, "epoch": group.1,
                }))
            }
            PROFILE_READ => {
                let room = p["roomId"].as_str().unwrap_or_default().to_string();
                Ok(match self.profile(&room) {
                    Some(profile) => json!({
                        "roomId": room, "status": "found", "profile": profile,
                        "author": TEST_VTC_DID, "issuedAt": "2026-10-16T09:00:00Z",
                        "epoch": 1, "version": 3, "stale": false,
                        "searched": { "fromEpoch": 1, "toEpoch": 1 },
                        "verification": { "trace": "verified", "priorRoots": "noneHeld" },
                    }),
                    None => json!({ "roomId": room, "status": "absent" }),
                })
            }
            PROFILE_WRITE => {
                let room = p["roomId"].as_str().unwrap_or_default().to_string();
                self.set_profile(&room, p["profile"].clone());
                Ok(json!({
                    "roomId": room, "outcome": "written", "key": "Qm4c8XkR2pVt7sLw0aJbYg",
                    "version": 4, "epoch": 1,
                }))
            }
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
                let from_now = self.0.lock().unwrap().issue_from_now;
                let credential = Self::credential(&room, kind, subject, p, from_now).await;
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
            GROUP_ADD => {
                let room = p["roomId"].as_str().unwrap().to_string();
                let member = p["member"].as_str().unwrap().to_string();
                let key_package = p["keyPackage"].as_str().unwrap_or_default().to_string();
                let mut st = self.0.lock().unwrap();
                if key_package == "bm90LWEta2V5LXBhY2thZ2U" {
                    return Err((
                        "rooms/owner/group/add:keyPackageInvalid",
                        "the KeyPackage cannot admit the member".into(),
                    ));
                }
                let kept = st.admitted.get(&room).cloned();
                let group = st.groups.get_mut(&room).expect("a group");
                if group.0.contains(&member) {
                    // Item 8: the identical request is answered with the kept Welcome.
                    return match kept {
                        Some((m, kp, epoch, welcome)) if m == member && kp == key_package => {
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
    vta.0.lock().unwrap().host = Some(vtc.state.room_revocations_ks.clone());
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

/// `vtc/rooms/memberships/list/0.1`: the community's one record of a member's rooms, which
/// every surface reads. An offer is `offered`; an acceptance — from any surface — is
/// `admitted` at once, with `repeatAcceptUntil` while a sealed room's Welcome is kept; a
/// removal is `removed` and keeps when they were admitted; a withdrawn offer is not listed.
#[tokio::test]
async fn every_surface_reads_one_record_of_a_members_rooms() {
    let mut fix = fixture().await;
    let sealed = create_room(&mut fix, "attributed").await;
    let open = create_room(&mut fix, "open").await;
    let withdrawn = create_room(&mut fix, "open").await;
    let alice = member(&fix).await;
    for room in [&sealed, &open, &withdrawn] {
        add_member(&mut fix, room, &alice.did, &in_a_year()).await;
    }
    let by_room = |list: &Value| -> std::collections::BTreeMap<String, Value> {
        list["payload"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| (i["roomId"].as_str().unwrap().to_string(), i.clone()))
            .collect()
    };

    let list = call_as(&fix, &alice, MEMBERSHIPS, json!({})).await;
    let rooms = by_room(&list);
    assert_eq!(rooms.len(), 3, "{list}");
    assert!(rooms.values().all(|r| r["state"] == "offered"), "{list}");
    assert!(
        rooms.values().all(|r| r.get("credentials").is_none()),
        "never a credential: those are collected with offers/list"
    );
    assert_eq!(rooms[&sealed]["host"], TEST_VTC_DID);
    assert_eq!(rooms[&sealed]["label"], "Board pack");

    // Withdrawn before it was accepted: never listed (item 3).
    admin_call(
        &mut fix,
        REMOVE,
        json!({ "roomId": withdrawn, "member": alice.did, "reason": "offered in error" }),
    )
    .await;

    // One surface accepts the open room, another the sealed one.
    let r = call_as(&fix, &alice, ACCEPT, json!({ "roomId": open })).await;
    assert_eq!(r["payload"]["state"], "admitted", "{r}");
    let first = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(first["payload"]["state"], "admitted", "{first}");

    let list = call_as(&fix, &alice, MEMBERSHIPS, json!({})).await;
    let rooms = by_room(&list);
    assert_eq!(rooms.len(), 2, "the withdrawn offer is gone: {list}");
    assert_eq!(rooms[&open]["state"], "admitted");
    assert!(rooms[&open]["admittedAt"].is_string());
    assert!(
        rooms[&open].get("repeatAcceptUntil").is_none(),
        "an open room has no Welcome"
    );
    assert_eq!(rooms[&sealed]["state"], "admitted");
    let until = rooms[&sealed]["repeatAcceptUntil"].as_str().unwrap();
    let admitted = rooms[&sealed]["admittedAt"].as_str().unwrap();
    let span = chrono::DateTime::parse_from_rfc3339(until).unwrap()
        - chrono::DateTime::parse_from_rfc3339(admitted).unwrap();
    assert_eq!(span, chrono::Duration::days(7), "{list}");

    // A second surface finishing the acceptance with the same KeyPackage changes nothing.
    let again = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(again["payload"]["welcome"], first["payload"]["welcome"]);
    assert_eq!(
        by_room(&call_as(&fix, &alice, MEMBERSHIPS, json!({})).await)[&sealed],
        rooms[&sealed]
    );

    // Paged in a stable order.
    let page = call_as(&fix, &alice, MEMBERSHIPS, json!({ "limit": 1 })).await;
    assert_eq!(page["payload"]["items"].as_array().unwrap().len(), 1);
    let cursor = page["payload"]["nextCursor"].as_str().unwrap().to_string();
    let rest = call_as(
        &fix,
        &alice,
        MEMBERSHIPS,
        json!({ "limit": 1, "cursor": cursor }),
    )
    .await;
    assert_eq!(rest["payload"]["items"].as_array().unwrap().len(), 1);
    assert!(rest["payload"].get("nextCursor").is_none(), "{rest}");
    assert_ne!(
        page["payload"]["items"][0]["roomId"],
        rest["payload"]["items"][0]["roomId"]
    );

    // Removed: still listed, with when they were admitted and removed.
    admin_call(
        &mut fix,
        REMOVE,
        json!({ "roomId": sealed, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    let list = call_as(&fix, &alice, MEMBERSHIPS, json!({})).await;
    let removed = &by_room(&list)[&sealed];
    assert_eq!(removed["state"], "removed", "{list}");
    assert!(removed["admittedAt"].is_string());
    assert!(removed["removedAt"].is_string());
    assert!(removed.get("repeatAcceptUntil").is_none());

    // Another member sees none of it.
    let bob = member(&fix).await;
    let theirs = call_as(&fix, &bob, MEMBERSHIPS, json!({})).await;
    assert_eq!(theirs["payload"]["items"], json!([]), "{theirs}");
}

/// `rooms/owner/group/add/0.3` item 8, end to end: the VTA admitted the member and its
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

/// The fix a client picks for a refusal: the first on the listing whose `when` names the
/// refusal's code and, if it lists any, a phrase its message contains.
fn chosen_fix<'a>(access: &'a Value, code: &str, message: &str) -> Option<&'a Value> {
    access["fixes"].as_array()?.iter().find(|f| {
        f["when"].as_array().into_iter().flatten().any(|w| {
            let refusal = w["refusal"].as_str().unwrap_or_default();
            let phrases: Vec<&str> = w["messageContains"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            code.ends_with(&format!(":{refusal}"))
                && (phrases.is_empty() || phrases.iter().any(|p| message.contains(p)))
        })
    })
}

/// A permission refusal at the community's VTA is answered on the listing — to a holder
/// of `vtc.rooms.manage` — with the `pnm` commands that fix it, filled in with this VTC's
/// DID and contexts. The refusal itself names no VTA context (framework *What a
/// `message` May Not Say*).
#[tokio::test]
async fn vtc_rooms_community_listing_carries_the_commands_that_fix_a_vta_refusal() {
    let mut fix = fixture().await;
    fix.vtc.state.config.write().await.vta_context = Some("vtc".into());
    fix.vta.script(MINT, Script::Refuse("permissionDenied"));
    let (_, r) = admin_call(
        &mut fix,
        CREATE,
        json!({ "label": "Board pack", "visibility": "open", "reason": "r" }),
    )
    .await;
    let code = tt_error_code(&r).unwrap().to_string();
    assert_eq!(code, CREATE_KEY_HOLDER_REFUSED, "{r}");
    let message = r["payload"]["message"].as_str().unwrap().to_string();
    assert!(!message.contains("pnm acl"), "{message}");

    let listed = call_as(&fix, &fix.admin, LIST, json!({})).await;
    let rooms = &listed["payload"]["ext"]["org.openvtc"]["communityRooms"];
    assert_eq!(rooms["enabled"], true, "{listed}");
    let access = &rooms["vtaAccess"];
    assert_eq!(access["vtcDid"], TEST_VTC_DID);
    assert_eq!(access["vtcDidContext"], "vtc");
    assert_eq!(access["roomsContext"], "vtc");
    assert_eq!(access["roomsContextInside"], true);
    assert!(access.get("warning").is_none(), "{access}");

    // The stand-in gave no reason: every command, with which one applies.
    let chosen = chosen_fix(access, &code, &message).expect("a permission refusal has a fix");
    assert_eq!(chosen["id"], "permission");
    let commands: Vec<&str> = chosen["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["command"].as_str().unwrap())
        .collect();
    assert!(
        commands.contains(&format!("pnm acl update {TEST_VTC_DID} --contexts vtc").as_str()),
        "{commands:?}"
    );
    assert_eq!(
        chosen["check"],
        "pnm acl list --context vtc --direction any"
    );

    // The persona refusal of the founding leaf: the entry's scope.
    let persona = format!(
        "the community's VTA refused: permissionDenied `{TEST_VTC_DID}` is not a persona you \
         may act as, so it cannot be the owner's leaf in room `did:x`"
    );
    assert_eq!(chosen_fix(access, &code, &persona).unwrap()["id"], "scope");
    // Not about permission: no fix.
    assert!(
        chosen_fix(
            access,
            &code,
            "the community's VTA refused: malformedRequest x"
        )
        .is_none()
    );
}

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
        record_retention: None,
        last_prune: None,
        epoch_floor: None,
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
        group_grants: Vec::new(),
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
    let r = call_as(&fix, &stranger, MEMBERSHIPS, json!({})).await;
    assert_eq!(
        tt_error_code(&r),
        Some(MEMBERSHIPS_LIST_NOT_A_MEMBER),
        "{r}"
    );
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

// ─── a member who leaves the community leaves its rooms (members/add item 6) ──

const SELF_REMOVE: &str = "https://trusttasks.org/spec/vtc/members/self-remove/0.1";
const ADMIN_REMOVE: &str = "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";

use vtc_service::rooms::community::{CommunityRooms, DepartureCause};
use vtc_service::rooms::departures;

/// `who` admitted to a sealed room and an open room, and offered a third (open) room.
/// Answers the three rooms: sealed, open, offered.
async fn in_three_rooms(fix: &mut Fixture, who: &Party) -> (String, String, String) {
    let sealed = create_room(fix, "attributed").await;
    let open = create_room(fix, "open").await;
    let offered = create_room(fix, "open").await;
    for room in [&sealed, &open, &offered] {
        add_member(fix, room, &who.did, &in_a_year()).await;
    }
    let a = call_as(
        fix,
        who,
        ACCEPT,
        json!({ "roomId": sealed, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(a["payload"]["state"], "admitted", "{a}");
    let a = call_as(fix, who, ACCEPT, json!({ "roomId": open })).await;
    assert_eq!(a["payload"]["state"], "admitted", "{a}");
    (sealed, open, offered)
}

async fn state_in(fix: &Fixture, room: &str, did: &str) -> String {
    fix.vtc
        .state
        .community_rooms
        .member(room, did)
        .await
        .unwrap()
        .expect("a record")
        .state
}

async fn owed(fix: &Fixture) -> Vec<(String, String, DepartureCause)> {
    fix.vtc
        .state
        .community_rooms
        .pending_removals()
        .await
        .unwrap()
        .into_iter()
        .map(|p| (p.room_id, p.member, p.cause))
        .collect()
}

/// A member who leaves is owed a removal from every room the community owns, recorded at
/// the departure itself — before the VTA is asked anything. The worker removes them as an
/// administrator's `members/remove/0.2` does (trust-tasks-tf #804): the open room's
/// admission and the offer are withdrawn at the host (`rooms/owner/revoke`), and the sealed
/// room's withdrawn and advanced past them (`rooms/owner/group/remove/0.3`), each at the
/// VTA before it is recorded; each is audited as the community's own act, naming the
/// departure. Rejoining re-adds nothing.
#[tokio::test]
async fn a_member_who_leaves_is_removed_from_every_community_room() {
    let mut fix = fixture().await;
    let alice = member(&fix).await;
    let (sealed, open, offered) = in_three_rooms(&mut fix, &alice).await;
    let bob = member(&fix).await;
    add_member(&mut fix, &open, &bob.did, &in_a_year()).await;

    fix.vta.clear_calls();
    let left = call_as(&fix, &alice, SELF_REMOVE, json!({})).await;
    assert_eq!(left["payload"]["removed"], true, "{left}");
    // Recorded at the departure; the VTA not yet asked.
    let mut want = vec![
        (sealed.clone(), alice.did.clone(), DepartureCause::Left),
        (open.clone(), alice.did.clone(), DepartureCause::Left),
        (offered.clone(), alice.did.clone(), DepartureCause::Left),
    ];
    want.sort_by(|a, b| a.0.cmp(&b.0));
    let mut got = owed(&fix).await;
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got, want);
    assert!(fix.vta.calls().is_empty());

    // Administrators see what is owed, where they read the room.
    let got = call_as(&fix, &fix.admin, GET, json!({ "roomId": sealed })).await;
    let ext = &got["payload"]["ext"]["org.openvtc"]["departureRemovals"];
    assert_eq!(ext[0]["member"], alice.did, "{got}");
    assert_eq!(ext[0]["cause"], "left");
    assert_eq!(ext[0]["status"], "pending");

    let report = departures::run_once(&fix.vtc.state, Utc::now())
        .await
        .unwrap();
    assert_eq!(report.removed, 3, "{report:?}");
    for room in [&sealed, &open, &offered] {
        assert_eq!(state_in(&fix, room, &alice.did).await, "removed");
        let r = fix
            .vtc
            .state
            .community_rooms
            .member(room, &alice.did)
            .await
            .unwrap()
            .unwrap();
        assert!(r.credentials.is_none(), "the offer's credentials are gone");
    }
    assert_eq!(
        state_in(&fix, &open, &bob.did).await,
        "offered",
        "nobody else moves"
    );
    assert!(owed(&fix).await.is_empty());
    // The sealed room's group was asked once, withdrawing first; the open room and the
    // offer were withdrawn at the host.
    let mut types = fix.vta.types_called();
    types.retain(|t| t == GROUP_REMOVE_V0_3 || t == OWNER_REVOKE);
    types.sort();
    assert_eq!(types, vec![GROUP_REMOVE_V0_3, OWNER_REVOKE, OWNER_REVOKE]);
    let calls = fix.vta.calls();
    let call = &calls
        .iter()
        .find(|(t, _)| t == GROUP_REMOVE_V0_3)
        .unwrap()
        .1;
    assert_eq!(call["member"], alice.did);
    assert_eq!(call["host"], TEST_VTC_DID);
    assert_eq!(call["reason"], DepartureCause::Left.reason());
    for (t, p) in calls.iter().filter(|(t, _)| t == OWNER_REVOKE) {
        assert_eq!(p["withdraw"][0]["subject"], alice.did, "{t}");
        assert_eq!(p["hosts"], json!([TEST_VTC_DID]));
    }
    let (members, _) = fix.vta.group(&sealed).unwrap();
    assert!(!members.contains(&alice.did));
    let got = call_as(&fix, &fix.admin, GET, json!({ "roomId": sealed })).await;
    assert!(
        got["payload"]["ext"]["org.openvtc"]
            .get("departureRemovals")
            .is_none(),
        "{got}"
    );

    let audit = audit_rows(&fix).await;
    assert!(audit.contains(DepartureCause::Left.reason()), "{audit}");
    assert!(audit.contains("offerWithdrawn"));

    // Idempotent: a second departure of the same member owes nothing more.
    assert_eq!(
        fix.vtc
            .state
            .community_rooms
            .record_departure(&alice.did, DepartureCause::Left, Utc::now())
            .await
            .unwrap(),
        0
    );

    // They rejoin: an active member again, and in no room.
    seed_role(&fix.vtc, &alice.did, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&alice.did))
        .await
        .unwrap();
    fix.vta.clear_calls();
    for later in [5, 10] {
        let report = departures::run_once(
            &fix.vtc.state,
            Utc::now() + chrono::Duration::minutes(later),
        )
        .await
        .unwrap();
        assert_eq!(report, departures::DriveReport::default());
    }
    for room in [&sealed, &open, &offered] {
        assert_eq!(state_in(&fix, room, &alice.did).await, "removed");
    }
    assert!(fix.vta.calls().is_empty());
    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    assert_eq!(offers["payload"]["items"], json!([]), "{offers}");
}

/// An administrator's removal of a member from the community is a departure too.
#[tokio::test]
async fn a_member_removed_from_the_community_is_owed_removal_from_its_rooms() {
    let mut fix = fixture().await;
    let alice = member(&fix).await;
    let open = create_room(&mut fix, "open").await;
    add_member(&mut fix, &open, &alice.did, &in_a_year()).await;
    let (status, reply) = admin_call(
        &mut fix,
        ADMIN_REMOVE,
        json!({ "did": alice.did, "reason": "conduct" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        owed(&fix).await,
        vec![(open.clone(), alice.did.clone(), DepartureCause::Removed)]
    );
    departures::run_once(&fix.vtc.state, Utc::now())
        .await
        .unwrap();
    assert_eq!(state_in(&fix, &open, &alice.did).await, "removed");
}

/// What no event announces — an entry that expired — and what a crash could cut off before
/// it was recorded — a suspended entry, an entry revoked with the member row still in place —
/// the reconciler finds, once it has seen it for the grace period. An active member is
/// left alone.
#[tokio::test]
async fn the_reconciler_finds_expired_suspended_and_revoked_entries() {
    let mut fix = fixture().await;
    let open = create_room(&mut fix, "open").await;
    let (bob, carol, dave, erin) = (
        member(&fix).await,
        member(&fix).await,
        member(&fix).await,
        member(&fix).await,
    );
    for p in [&bob, &carol, &dave, &erin] {
        add_member(&mut fix, &open, &p.did, &in_a_year()).await;
    }
    let acl = &fix.vtc.state.acl_ks;
    let mut entry = vtc_service::acl::get_acl_entry(acl, &bob.did)
        .await
        .unwrap()
        .unwrap();
    entry.expires_at = Some(1);
    vtc_service::acl::store_acl_entry(acl, &entry)
        .await
        .unwrap();
    vtc_service::acl::storage::put_suspension(
        acl,
        &carol.did,
        &vtc_service::acl::Suspension {
            action_id: "a1".into(),
            lands_at: u64::MAX,
            requester: fix.admin.did.clone(),
        },
    )
    .await
    .unwrap();
    vtc_service::acl::delete_acl_entry(acl, &dave.did)
        .await
        .unwrap();

    let now = Utc::now();
    assert_eq!(
        departures::reconcile(&fix.vtc.state, now).await.unwrap(),
        0,
        "nothing is acted on before the grace period"
    );
    assert_eq!(
        departures::reconcile(&fix.vtc.state, now + departures::GRACE)
            .await
            .unwrap(),
        3
    );
    let mut got = owed(&fix).await;
    got.sort_by(|a, b| a.1.cmp(&b.1));
    let mut want = vec![
        (open.clone(), bob.did.clone(), DepartureCause::Expired),
        (open.clone(), carol.did.clone(), DepartureCause::Suspended),
        (open.clone(), dave.did.clone(), DepartureCause::AclRemoved),
    ];
    want.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(got, want);
    departures::drive(&fix.vtc.state, now + departures::GRACE)
        .await
        .unwrap();
    for p in [&bob, &carol, &dave] {
        assert_eq!(state_in(&fix, &open, &p.did).await, "removed");
    }
    assert_eq!(state_in(&fix, &open, &erin.did).await, "offered");
}

/// A departure does not wait on the community's VTA. One that does not answer is retried
/// with backoff — and the room's reads say so — until it does; an attempt whose answer was
/// lost is settled by the next, which the VTA answers `notMember`.
#[tokio::test]
async fn an_unreachable_vta_is_retried_until_the_removal_completes() {
    let mut fix = fixture().await;
    let alice = member(&fix).await;
    let room = create_room(&mut fix, "attributed").await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;

    fix.vta.script(GROUP_REMOVE_V0_3, Script::Silent);
    let left = call_as(&fix, &alice, SELF_REMOVE, json!({})).await;
    assert_eq!(
        left["payload"]["removed"], true,
        "the departure is not held up: {left}"
    );

    let t0 = Utc::now();
    let report = departures::run_once(&fix.vtc.state, t0).await.unwrap();
    assert_eq!(report.retrying, 1, "{report:?}");
    assert_eq!(state_in(&fix, &room, &alice.did).await, "admitted");
    let listed = call_as(&fix, &fix.admin, MEMBERS, json!({ "roomId": room })).await;
    let owed_row = &listed["payload"]["ext"]["org.openvtc"]["departureRemovals"][0];
    assert_eq!(owed_row["status"], "retrying", "{listed}");
    assert_eq!(owed_row["attempts"], 1);
    assert!(
        owed_row["lastError"]
            .as_str()
            .unwrap()
            .contains("could not be reached")
    );

    // Not due yet: the VTA is not asked again.
    fix.vta.clear_calls();
    departures::run_once(&fix.vtc.state, t0 + chrono::Duration::seconds(10))
        .await
        .unwrap();
    assert!(fix.vta.calls().is_empty());

    // Due: the VTA removes them, and the answer is lost.
    fix.vta.script(GROUP_REMOVE_V0_3, Script::ServeThenSilent);
    let t1 = t0 + departures::backoff(1);
    let report = departures::run_once(&fix.vtc.state, t1).await.unwrap();
    assert_eq!(report.retrying, 1, "{report:?}");
    let (members, epoch) = fix.vta.group(&room).unwrap();
    assert!(!members.contains(&alice.did), "the VTA did remove them");
    assert_eq!(state_in(&fix, &room, &alice.did).await, "admitted");

    // The next attempt is answered `notMember`: removed is what is true.
    let report = departures::run_once(&fix.vtc.state, t1 + departures::backoff(2))
        .await
        .unwrap();
    assert_eq!(report.removed, 1, "{report:?}");
    assert_eq!(state_in(&fix, &room, &alice.did).await, "removed");
    assert_eq!(fix.vta.group(&room).unwrap().1, epoch, "advanced once");
    assert!(owed(&fix).await.is_empty());
}

/// Owed removals are durable: a restarted service — nothing in memory — resumes them from
/// the keyspace. And an administrator who removes the member by hand meanwhile settles the
/// one owed in that room.
#[tokio::test]
async fn owed_removals_survive_a_restart_and_yield_to_a_manual_removal() {
    let mut fix = fixture().await;
    let alice = member(&fix).await;
    let (sealed, open, offered) = in_three_rooms(&mut fix, &alice).await;
    fix.vta.script(GROUP_REMOVE_V0_3, Script::Silent);
    call_as(&fix, &alice, SELF_REMOVE, json!({})).await;
    // The sealed room's VTA does not answer. Every removal asks the VTA now — the open
    // room's and the offer's withdraw their credentials at the host — so the pass stops at
    // the first silence and whatever it had not reached stays owed.
    departures::run_once(&fix.vtc.state, Utc::now())
        .await
        .unwrap();
    assert_eq!(state_in(&fix, &sealed, &alice.did).await, "admitted");
    let mut still = 0;
    for room in [&sealed, &open, &offered] {
        if state_in(&fix, room, &alice.did).await != "removed" {
            still += 1;
        }
    }
    assert!(still >= 1);
    assert_eq!(owed(&fix).await.len(), still);

    // A restart: the same keyspace, a fresh service around it.
    let mut restarted = fix.vtc.state.clone();
    restarted.community_rooms = CommunityRooms::new(
        fix.vtc.state.community_rooms.keyspace().clone(),
        Some(Arc::new(fix.vta.clone())),
    );
    let report = departures::run_once(&restarted, Utc::now() + chrono::Duration::hours(2))
        .await
        .unwrap();
    assert_eq!(report.removed, still, "{report:?}");
    for room in [&sealed, &open, &offered] {
        assert_eq!(state_in(&fix, room, &alice.did).await, "removed");
    }

    // By hand: an owed removal is settled by the administrator's.
    let bob = member(&fix).await;
    add_member(&mut fix, &open, &bob.did, &in_a_year()).await;
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &bob.did)
        .await
        .unwrap();
    fix.vtc
        .state
        .community_rooms
        .record_departure(&bob.did, DepartureCause::AclRemoved, Utc::now())
        .await
        .unwrap();
    let (_, removed) = admin_call(
        &mut fix,
        REMOVE,
        json!({ "roomId": open, "member": bob.did, "reason": "left" }),
    )
    .await;
    assert_eq!(
        removed["payload"]["member"]["state"], "removed",
        "{removed}"
    );
    assert!(owed(&fix).await.is_empty());
}

// ─── a room's details: label, description, tags ─────────────────────────

/// An administrator holding hosting's `vtc.rooms.admin` and not the owner's
/// `vtc.rooms.manage`.
async fn host_admin_only(fix: &Fixture) -> Party {
    let narrow = Party::new();
    let row = vtc_service::acl::VtcAclEntry {
        did: narrow.did.clone(),
        role: VtcRole::Admin,
        label: None,
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
        group_grants: Vec::new(),
        label_set_by_subject: false,
        suspension: None,
    };
    vtc_service::acl::store_acl_entry(&fix.vtc.state.acl_ks, &row)
        .await
        .unwrap();
    narrow
}

/// A room created at 0.2 with a description and tags.
async fn create_described(fix: &mut Fixture, label: &str, tags: Value) -> String {
    let (status, reply) = admin_call(
        fix,
        CREATE_V0_2,
        json!({
            "label": label, "visibility": "open", "reason": "the board's papers",
            "description": "Papers for the board's meetings.", "tags": tags,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let room = &reply["payload"]["room"];
    assert_eq!(room["description"], "Papers for the board's meetings.");
    assert!(
        room.get("detailsUpdatedAt").is_none(),
        "absent until the first change after creation"
    );
    room["room"]["roomId"].as_str().unwrap().to_string()
}

/// Every `detailsUpdated` row, parsed.
async fn details_rows(fix: &Fixture) -> Vec<Value> {
    let mut out = Vec::new();
    for (_, raw) in fix
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
    {
        let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        if v.to_string().contains("\"detailsUpdated\"") {
            out.push(v);
        }
    }
    out
}

/// The one row's `details`, wherever the audit envelope nests the event data.
fn row_details(row: &Value) -> Value {
    fn find(v: &Value) -> Option<Value> {
        match v {
            Value::Object(m) => {
                if m.get("event").and_then(Value::as_str) == Some("detailsUpdated") {
                    return Some(Value::Object(m.clone()));
                }
                m.values().find_map(find)
            }
            Value::Array(a) => a.iter().find_map(find),
            _ => None,
        }
    }
    find(row).expect("a detailsUpdated event")
}

/// `vtc/rooms/community/update/0.1` items 3–6: each detail given replaces the stored one
/// and the rest are left alone, `tags: []` clears, `removeDescription` removes, a request
/// that changes nothing writes nothing — no details, no `detailsUpdated*`, no audit row —
/// and every change is one audit row with each changed detail's previous and new value.
#[tokio::test]
async fn vtc_rooms_community_update_replaces_what_it_names_and_nothing_else() {
    let mut fix = fixture().await;
    let room = create_described(&mut fix, "Board pack", json!(["finance", "board"])).await;
    let hosted_before = vti_rooms::storage::get_room(&fix.vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    fix.vta.clear_calls();

    // A rename: label only, so the description and tags stay. No step-up is asked for:
    // `call_as` sends with none.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": room, "label": "Board pack — 2027", "reason": "the 2027 cycle" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], true, "{r}");
    let after = &r["payload"]["room"];
    assert_eq!(after["label"], "Board pack — 2027");
    assert_eq!(after["description"], "Papers for the board's meetings.");
    assert_eq!(after["tags"], json!(["board", "finance"]));
    assert_eq!(after["detailsUpdatedBy"], fix.admin.did);
    let first_change = after["detailsUpdatedAt"].clone();
    assert!(first_change.is_string());

    // Item 8: nothing reached the VTA, and the host record did not move.
    assert!(fix.vta.calls().is_empty(), "{:?}", fix.vta.types_called());
    let hosted_after = vti_rooms::storage::get_room(&fix.vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    assert_eq!(hosted_after.updated_at, hosted_before.updated_at);
    assert_eq!(hosted_after.epoch, hosted_before.epoch);

    // Item 6: one row, naming the requester, the room, the label before and after, and
    // the reason — and only the detail that changed.
    let rows = details_rows(&fix).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = row_details(&rows[0]);
    assert_eq!(d["roomId"], room);
    assert_eq!(d["reason"], "the 2027 cycle");
    assert_eq!(
        d["details"],
        json!([{ "field": "label", "old": "Board pack", "new": "Board pack — 2027" }])
    );
    assert_eq!(
        rows[0]["actor_did_plain"], fix.admin.did,
        "the requester is recorded: {}",
        rows[0]
    );

    // Item 4: the same values again — tags in another order, a set — change nothing,
    // write nothing and audit nothing.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({
            "roomId": room, "label": "Board pack — 2027",
            "description": "Papers for the board's meetings.",
            "tags": ["finance", "board"], "reason": "again",
        }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], false, "{r}");
    assert_eq!(r["payload"]["room"]["detailsUpdatedAt"], first_change);
    assert_eq!(details_rows(&fix).await.len(), 1, "a no-op is not audited");

    // `tags: []` clears them; the description is untouched.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": room, "tags": [], "reason": "no filing" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], true, "{r}");
    assert!(r["payload"]["room"].get("tags").is_none(), "{r}");
    assert_eq!(
        r["payload"]["room"]["description"],
        "Papers for the board's meetings."
    );
    let rows = details_rows(&fix).await;
    assert_eq!(
        row_details(rows.last().unwrap())["details"],
        json!([{ "field": "tags", "old": ["board", "finance"] }])
    );

    // `removeDescription` removes it.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": room, "removeDescription": true, "reason": "named a supplier" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], true, "{r}");
    assert!(r["payload"]["room"].get("description").is_none(), "{r}");
    // Removing what is not there is a no-op.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": room, "removeDescription": true, "reason": "again" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], false, "{r}");

    // The schema's own rules: a description and its removal together, and a request
    // naming no detail, are malformed.
    for bad in [
        json!({ "roomId": room, "description": "x", "removeDescription": true, "reason": "r" }),
        json!({ "roomId": room, "reason": "r" }),
        json!({ "roomId": room, "tags": ["Not A Tag"], "reason": "r" }),
    ] {
        let r = call_as(&fix, &fix.admin, UPDATE, bad.clone()).await;
        assert_eq!(tt_error_code(&r), Some("malformedRequest"), "{bad}: {r}");
    }
}

/// Item 2: `notFound` for a room the community only hosts, and nothing kept for it.
/// Item 1: `permissionDenied` without `vtc.rooms.manage`, `vtc.rooms.admin` alone
/// included.
#[tokio::test]
async fn vtc_rooms_community_update_answers_not_found_for_a_room_it_only_hosts() {
    let mut fix = fixture().await;
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
        record_retention: None,
        last_prune: None,
        epoch_floor: None,
    };
    vti_rooms::storage::create_room(&fix.vtc.state.rooms_ks, &hosted)
        .await
        .unwrap();
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": hosted.room_id, "label": "Somebody's room", "reason": "naming it" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(UPDATE_NOT_FOUND), "{r}");
    assert!(
        fix.vtc
            .state
            .community_rooms
            .room(&hosted.room_id)
            .await
            .unwrap()
            .is_none(),
        "no label is kept for a room the community does not own"
    );
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": "did:key:z6MkNobody", "label": "x", "reason": "r" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some(UPDATE_NOT_FOUND), "{r}");

    let room = create_room(&mut fix, "open").await;
    let narrow = host_admin_only(&fix).await;
    let r = call_as(
        &fix,
        &narrow,
        UPDATE,
        json!({ "roomId": room, "label": "Mine now", "reason": "r" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some("permissionDenied"), "{r}");
    let alice = member(&fix).await;
    let r = call_as(
        &fix,
        &alice,
        UPDATE,
        json!({ "roomId": room, "label": "Mine now", "reason": "r" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), Some("permissionDenied"), "{r}");
    let got = call_as(&fix, &fix.admin, GET, json!({ "roomId": room })).await;
    assert_eq!(got["payload"]["room"]["label"], "Board pack");
}

/// 0.1 keeps exactly the shape it published; 0.2 carries the details. `list/0.2`'s `tag`
/// lists only the rooms carrying it, paged within the filter.
#[tokio::test]
async fn vtc_rooms_community_reads_answer_each_version_in_its_shape() {
    let mut fix = fixture().await;
    let board = create_described(&mut fix, "Board pack", json!(["board"])).await;
    let library = create_described(&mut fix, "Library", json!(["library"])).await;
    let plain = create_room(&mut fix, "open").await;

    // 0.1: no description, tags or `detailsUpdated*`, whatever the room has.
    let got = call_as(&fix, &fix.admin, GET, json!({ "roomId": board })).await;
    for absent in [
        "description",
        "tags",
        "detailsUpdatedAt",
        "detailsUpdatedBy",
    ] {
        assert!(
            got["payload"]["room"].get(absent).is_none(),
            "{absent}: {got}"
        );
    }
    let listed = call_as(&fix, &fix.admin, LIST, json!({})).await;
    assert_eq!(listed["payload"]["items"].as_array().unwrap().len(), 3);
    assert!(
        listed["payload"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i.get("tags").is_none())
    );

    // 0.2.
    let got = call_as(&fix, &fix.admin, GET_V0_2, json!({ "roomId": board })).await;
    assert_eq!(got["payload"]["room"]["tags"], json!(["board"]), "{got}");
    let got = call_as(&fix, &fix.admin, GET_V0_2, json!({ "roomId": plain })).await;
    assert!(got["payload"]["room"].get("tags").is_none(), "{got}");
    assert!(got["payload"]["room"].get("description").is_none(), "{got}");

    let ids = |v: &Value| -> Vec<String> {
        v["payload"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["room"]["roomId"].as_str().unwrap().to_string())
            .collect()
    };
    let all = call_as(&fix, &fix.admin, LIST_V0_2, json!({})).await;
    assert_eq!(ids(&all).len(), 3, "{all}");
    let tagged = call_as(&fix, &fix.admin, LIST_V0_2, json!({ "tag": "board" })).await;
    assert_eq!(ids(&tagged), vec![board.clone()], "{tagged}");
    let none = call_as(&fix, &fix.admin, LIST_V0_2, json!({ "tag": "nothing" })).await;
    assert_eq!(none["payload"]["items"], json!([]), "{none}");

    // Paging within the filter: tag both, one per page.
    for r in [&board, &library] {
        call_as(
            &fix,
            &fix.admin,
            UPDATE,
            json!({ "roomId": r, "tags": ["shared"], "reason": "file together" }),
        )
        .await;
    }
    let page1 = call_as(
        &fix,
        &fix.admin,
        LIST_V0_2,
        json!({ "tag": "shared", "limit": 1 }),
    )
    .await;
    assert_eq!(ids(&page1).len(), 1);
    let next = page1["payload"]["nextCursor"].as_str().unwrap().to_string();
    let page2 = call_as(
        &fix,
        &fix.admin,
        LIST_V0_2,
        json!({ "tag": "shared", "cursor": next, "limit": 1 }),
    )
    .await;
    assert_eq!(ids(&page2).len(), 1);
    assert!(page2["payload"].get("nextCursor").is_none(), "{page2}");
    let mut both = [ids(&page1), ids(&page2)].concat();
    both.sort();
    let mut want = vec![board, library];
    want.sort();
    assert_eq!(both, want);
}

/// `vtc/rooms/offers/list/0.2` item 4: the room's current label and description — a rename
/// reaches an open offer — and never its tags. 0.1 shows the label only.
#[tokio::test]
async fn vtc_rooms_offers_list_shows_the_rooms_description_and_never_its_tags() {
    let mut fix = fixture().await;
    let room = create_described(&mut fix, "Board pack", json!(["board"])).await;
    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({
            "roomId": room, "label": "Board pack — 2027",
            "description": "Agendas, minutes and the finance pack.", "reason": "2027",
        }),
    )
    .await;

    let offers = call_as(&fix, &alice, OFFERS_V0_2, json!({})).await;
    let offer = &offers["payload"]["items"][0];
    assert_eq!(offer["label"], "Board pack — 2027", "{offers}");
    assert_eq!(
        offer["description"],
        "Agendas, minutes and the finance pack."
    );
    assert!(offer.get("tags").is_none(), "{offer}");
    assert!(!offers.to_string().contains("\"board\""), "{offers}");

    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    let offer = &offers["payload"]["items"][0];
    assert_eq!(offer["label"], "Board pack — 2027");
    assert!(offer.get("description").is_none(), "{offer}");
}

// ─── the room's own profile (create 0.3, update 0.2) ────────────────────

/// The `rooms/keys/profile/write` requests the stand-in received, in order.
fn profile_writes(fix: &Fixture) -> Vec<Value> {
    fix.vta
        .calls()
        .into_iter()
        .filter(|(t, _)| t == PROFILE_WRITE)
        .map(|(_, p)| p)
        .collect()
}

async fn create_v0_3(fix: &mut Fixture, label: &str, visibility: &str) -> Value {
    let (status, reply) = admin_call(
        fix,
        CREATE_V0_3,
        json!({
            "label": label, "visibility": visibility, "reason": "the board's papers",
            "description": "Papers for the board's meetings.", "tags": ["board", "finance"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply
}

/// `vtc/rooms/community/create/0.3` step 5 and items 8–9: once the room is stored, the
/// community's own VTA is asked to write the label as the profile's `name` and the
/// description as its `description` — **never the tags** — as the community, with this
/// community as the host; the answer is `written`, and the room's `get` says so.
#[tokio::test]
async fn vtc_rooms_community_create_0_3_writes_label_and_description_as_the_rooms_profile() {
    let mut fix = fixture().await;
    let reply = create_v0_3(&mut fix, "Board pack", "attributed").await;
    let room = reply["payload"]["room"]["room"]["roomId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(reply["payload"]["roomProfile"], "written", "{reply}");

    let writes = profile_writes(&fix);
    assert_eq!(writes.len(), 1, "{:?}", fix.vta.types_called());
    let w = &writes[0];
    assert_eq!(w["roomId"], room);
    assert_eq!(w["host"], TEST_VTC_DID, "the community is the room's host");
    assert_eq!(
        w["profile"],
        json!({ "name": "Board pack", "description": "Papers for the board's meetings." }),
        "tags are administrators' filing and never go into the room"
    );
    assert_eq!(
        w["ext"]["org.openvtc.rooms"]["member"], TEST_VTC_DID,
        "written as the community's own place in the room"
    );
    // Remote first: the room was stored before the profile was asked for.
    let types = fix.vta.types_called();
    assert_eq!(
        types.last().map(String::as_str),
        Some(PROFILE_WRITE),
        "{types:?}"
    );

    let (_, got) = admin_call(&mut fix, GET_V0_2, json!({ "roomId": room })).await;
    assert_eq!(
        got["payload"]["ext"]["org.openvtc"]["roomProfile"]["state"], "written",
        "{got}"
    );
    // Nothing of the profile reached the host's record of the room.
    let hosted = vti_rooms::storage::get_room(&fix.vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    assert!(
        !serde_json::to_string(&hosted)
            .unwrap()
            .contains("Board pack")
    );
}

/// Item 9: a profile the VTA did not write does not fail the create or remove the room —
/// the answer is `pending`, the room stands, and the sweeper, the one retry owner, writes
/// it on a later pass.
#[tokio::test]
async fn vtc_rooms_community_create_0_3_answers_pending_and_the_sweeper_writes_it() {
    let mut fix = fixture().await;
    fix.vta.script(
        PROFILE_WRITE,
        Script::Refuse("rooms/keys/profile/write:hostUnreachable"),
    );
    let reply = create_v0_3(&mut fix, "Board pack", "attributed").await;
    assert_eq!(reply["payload"]["roomProfile"], "pending", "{reply}");
    let room = reply["payload"]["room"]["room"]["roomId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        fix.vtc
            .state
            .community_rooms
            .room(&room)
            .await
            .unwrap()
            .is_some()
    );
    let (_, got) = admin_call(&mut fix, GET_V0_2, json!({ "roomId": room })).await;
    let state = &got["payload"]["ext"]["org.openvtc"]["roomProfile"];
    assert_eq!(state["state"], "pending", "{got}");
    assert_eq!(state["attempts"], 1);
    assert!(
        state["lastError"]
            .as_str()
            .unwrap()
            .contains("hostUnreachable")
    );

    // Before its backoff ends the sweeper leaves it; after, it writes it.
    let report = vtc_service::rooms::community_profile::sweep(&fix.vtc.state, Utc::now())
        .await
        .unwrap();
    assert!(report.written.is_empty(), "{report:?}");
    let later = Utc::now() + chrono::Duration::hours(7);
    let report = vtc_service::rooms::community_profile::sweep(&fix.vtc.state, later)
        .await
        .unwrap();
    assert_eq!(report.written, vec![room.clone()]);
    assert_eq!(fix.vta.profile(&room).unwrap()["name"], "Board pack");
    let (_, got) = admin_call(&mut fix, GET_V0_2, json!({ "roomId": room })).await;
    assert_eq!(
        got["payload"]["ext"]["org.openvtc"]["roomProfile"]["state"], "written",
        "{got}"
    );
    // And a written room is not written again.
    fix.vta.clear_calls();
    let report = vtc_service::rooms::community_profile::sweep(&fix.vtc.state, later)
        .await
        .unwrap();
    assert!(report.written.is_empty() && profile_writes(&fix).is_empty());
}

/// `vtc/rooms/community/update/0.2` items 10–11: a rename writes the profile again,
/// carrying over the tags and emoji a curator set in the room; a change of the
/// administrators' tags alone writes nothing (`unchanged`); and the change to the
/// community's own record stands whatever the VTA answers.
#[tokio::test]
async fn vtc_rooms_community_update_0_2_rewrites_the_profile_on_a_rename_only() {
    let mut fix = fixture().await;
    let reply = create_v0_3(&mut fix, "Board pack", "attributed").await;
    let room = reply["payload"]["room"]["room"]["roomId"]
        .as_str()
        .unwrap()
        .to_string();
    // A curator gave the room tags and an emoji of its own, in the room.
    fix.vta.set_profile(
        &room,
        json!({ "name": "Board pack", "description": "Papers for the board's meetings.",
                "tags": ["minutes"], "emoji": "📋" }),
    );
    fix.vta.clear_calls();

    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "label": "Board pack — 2027", "reason": "the 2027 cycle" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], true, "{r}");
    assert_eq!(r["payload"]["roomProfile"], "written", "{r}");
    assert_eq!(
        fix.vta.profile(&room).unwrap(),
        json!({ "name": "Board pack — 2027", "description": "Papers for the board's meetings.",
                "tags": ["minutes"], "emoji": "📋" }),
        "the members the community does not manage are carried over"
    );

    // Tags only: the administrators' filing, never in the room.
    fix.vta.clear_calls();
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "tags": ["archive"], "reason": "filed" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], true, "{r}");
    assert_eq!(r["payload"]["roomProfile"], "unchanged", "{r}");
    assert!(profile_writes(&fix).is_empty());

    // Nothing at all: unchanged, nothing written.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "label": "Board pack — 2027", "reason": "again" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], false, "{r}");
    assert_eq!(r["payload"]["roomProfile"], "unchanged", "{r}");

    // Removing the description writes a profile without one; a VTA that refuses leaves
    // it pending and the update stands.
    fix.vta.script(
        PROFILE_WRITE,
        Script::Refuse("rooms/keys/profile/write:contended"),
    );
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "removeDescription": true, "reason": "named a supplier" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], true, "{r}");
    assert_eq!(r["payload"]["roomProfile"], "pending", "{r}");
    assert!(r["payload"]["room"].get("description").is_none(), "{r}");
    // A later update supersedes the pending one: what is written is the room as it is.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "tags": ["archive", "minutes"], "reason": "refiled" }),
    )
    .await;
    assert_eq!(r["payload"]["roomProfile"], "written", "{r}");
    let written = fix.vta.profile(&room).unwrap();
    assert_eq!(written["name"], "Board pack — 2027");
    assert!(written.get("description").is_none(), "{written}");
}

/// Item 10: a room made before create 0.3 has never had its profile written, so the first
/// update 0.2 writes it even when it changes nothing — and audits no change. Update 0.1
/// never reaches the VTA.
#[tokio::test]
async fn vtc_rooms_community_update_0_2_writes_the_profile_of_a_room_made_before_create_0_3() {
    let mut fix = fixture().await;
    let room = create_described(&mut fix, "Board pack", json!(["board"])).await;
    fix.vta.clear_calls();

    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE,
        json!({ "roomId": room, "label": "Board pack", "reason": "nothing" }),
    )
    .await;
    assert!(r["payload"].get("roomProfile").is_none(), "{r}");
    assert!(
        fix.vta.calls().is_empty(),
        "0.1 keeps the details out of the VTA"
    );

    let audited = details_rows(&fix).await.len();
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "label": "Board pack", "reason": "nothing" }),
    )
    .await;
    assert_eq!(r["payload"]["changed"], false, "{r}");
    assert_eq!(r["payload"]["roomProfile"], "written", "{r}");
    assert_eq!(fix.vta.profile(&room).unwrap()["name"], "Board pack");
    assert_eq!(
        details_rows(&fix).await.len(),
        audited,
        "not audited as a change"
    );

    // Written once; the next no-op update has nothing to write.
    let r = call_as(
        &fix,
        &fix.admin,
        UPDATE_V0_2,
        json!({ "roomId": room, "label": "Board pack", "reason": "nothing" }),
    )
    .await;
    assert_eq!(r["payload"]["roomProfile"], "unchanged", "{r}");
}

// ─── vtc/rooms/community/members/remove/0.2 (trust-tasks-tf #804) ───────────────

/// An offer accepted on an open room, and the presentation its credentials make.
async fn admitted_on_open_room(fix: &mut Fixture) -> (String, Party, Value) {
    let room = create_room(fix, "open").await;
    let alice = member(fix).await;
    add_member(fix, &room, &alice.did, &in_a_year()).await;
    let offers = call_as(fix, &alice, OFFERS, json!({})).await;
    let offer = offers["payload"]["items"][0].clone();
    let accepted = call_as(fix, &alice, ACCEPT, json!({ "roomId": room })).await;
    assert_eq!(accepted["payload"]["state"], "admitted", "{accepted}");
    let presentation = json!({
        "membership": offer["credentials"]["membership"],
        "authority": [offer["credentials"]["authority"]],
    });
    (room, alice, presentation)
}

async fn read_as(fix: &Fixture, who: &Party, room: &str, presentation: &Value) -> Value {
    call_as(
        fix,
        who,
        vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
        json!({ "roomId": room, "presentation": presentation }),
    )
    .await
}

/// Item 2, `open`: the VTA withdraws the member (`rooms/owner/revoke`, one `subject`
/// withdrawal delivered to this community as the room's host), and from then on this
/// community refuses the credentials the offer gave them — the removal takes effect at
/// the host at once. The answer carries the list's head and `revokedAt`, and no epoch.
#[tokio::test]
async fn removal_0_2_on_an_open_room_withdraws_the_member_at_the_host() {
    let mut fix = fixture().await;
    let (room, alice, presentation) = admitted_on_open_room(&mut fix).await;
    let read = read_as(&fix, &alice, &room, &presentation).await;
    assert!(
        read["payload"]["records"].is_array(),
        "reads before: {read}"
    );

    fix.vta.clear_calls();
    let (status, removed) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    let p = &removed["payload"];
    assert_eq!(p["member"]["state"], "removed");
    assert_eq!(p["revocation"]["sequence"], 1, "{removed}");
    assert!(p["revokedAt"].is_string());
    assert!(p.get("epoch").is_none());

    let calls = fix.vta.calls();
    assert_eq!(fix.vta.types_called(), vec![OWNER_REVOKE]);
    assert_eq!(calls[0].1["hosts"], json!([TEST_VTC_DID]));
    assert_eq!(calls[0].1["withdraw"][0]["kind"], "subject");
    assert_eq!(calls[0].1["withdraw"][0]["subject"], alice.did);

    let refused = read_as(&fix, &alice, &room, &presentation).await;
    assert_eq!(error_code(&refused), Some("permissionDenied"), "{refused}");
}

/// Item 2, `attributed`: `rooms/owner/group/remove` at 0.3 — withdraw first, then advance.
#[tokio::test]
async fn removal_0_2_on_an_attributed_room_withdraws_then_advances() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;

    fix.vta.clear_calls();
    let (_, removed) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    let p = &removed["payload"];
    assert_eq!(p["epoch"], 3, "{removed}");
    assert_eq!(p["revocation"]["sequence"], 1);
    assert!(p["revokedAt"].is_string());
    assert_eq!(fix.vta.types_called(), vec![GROUP_REMOVE_V0_3]);
    let call = &fix.vta.calls()[0].1;
    assert_eq!(call["host"], TEST_VTC_DID);
    assert!(call["signingKeyId"].is_string());
    assert_eq!(
        fix.vta.group(&room).unwrap().0,
        vec![TEST_VTC_DID.to_string()]
    );
}

/// Item 3: an open offer is withdrawn, and on `open` and `attributed` rooms its
/// credentials at the host too — a member may already have collected them.
#[tokio::test]
async fn removal_0_2_withdraws_an_open_offers_credentials() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    fix.vta.clear_calls();
    let (_, removed) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "changed our minds" }),
    )
    .await;
    assert_eq!(
        removed["payload"]["member"]["state"], "removed",
        "{removed}"
    );
    assert_eq!(removed["payload"]["revocation"]["sequence"], 1);
    assert!(removed["payload"].get("epoch").is_none());
    assert_eq!(fix.vta.types_called(), vec![OWNER_REVOKE]);
}

/// Item 2: a withdrawal the host did not accept is never a removal — the VTA's refusal
/// is `keyHolderRefused`, its silence `keyHolderUnavailable`, and nothing is recorded.
#[tokio::test]
async fn removal_0_2_records_nothing_until_the_withdrawal_is_accepted() {
    let mut fix = fixture().await;
    let (room, alice, _) = admitted_on_open_room(&mut fix).await;

    fix.vta.script(
        OWNER_REVOKE,
        Script::Refuse("rooms/owner/revoke:noAuthority"),
    );
    let (_, refused) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(
        error_code(&refused),
        Some(REMOVE_KEY_HOLDER_REFUSED),
        "{refused}"
    );

    fix.vta.script(OWNER_REVOKE, Script::Silent);
    let (_, silent) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(
        error_code(&silent),
        Some(REMOVE_KEY_HOLDER_UNAVAILABLE),
        "{silent}"
    );
    let members = call_as(&fix, &fix.admin, MEMBERS, json!({ "roomId": room })).await;
    assert_eq!(members["payload"]["items"][0]["state"], "admitted");
}

/// Re-admission after a removal works: the withdrawal is keyed on time, and the fresh
/// credentials a second offer gives postdate it.
#[tokio::test]
async fn a_member_removed_at_0_2_can_be_admitted_again() {
    let mut fix = fixture().await;
    let (room, alice, _) = admitted_on_open_room(&mut fix).await;
    admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    // Issued from now, as the VTA issues them: after the withdrawal. A credential's
    // `validFrom` is written to the second, so one issued within the second of a
    // withdrawal reads as issued before it and stays withdrawn — fail closed.
    fix.vta.0.lock().unwrap().issue_from_now = true;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    let offers = call_as(&fix, &alice, OFFERS, json!({})).await;
    let offer = offers["payload"]["items"][0].clone();
    call_as(&fix, &alice, ACCEPT, json!({ "roomId": room })).await;
    let presentation = json!({
        "membership": offer["credentials"]["membership"],
        "authority": [offer["credentials"]["authority"]],
    });
    let read = read_as(&fix, &alice, &room, &presentation).await;
    assert!(read["payload"]["records"].is_array(), "re-admitted: {read}");
}

/// An `attributed` room with Alice admitted and joined, ready for a removal.
async fn joined_on_attributed_room(fix: &mut Fixture) -> (String, Party) {
    let room = create_room(fix, "attributed").await;
    let alice = member(fix).await;
    add_member(fix, &room, &alice.did, &in_a_year()).await;
    call_as(
        fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    fix.vta.clear_calls();
    (room, alice)
}

/// `rooms/owner/group/remove/0.3` item 8.2: the VTA gave up an earlier removal it was
/// settling and did nothing of this one. The administrator is told so — and what to do —
/// nothing is recorded, and repeating the removal proceeds.
#[tokio::test]
async fn an_earlier_removal_the_vta_gave_up_is_surfaced_and_nothing_is_recorded() {
    let mut fix = fixture().await;
    let (room, alice) = joined_on_attributed_room(&mut fix).await;
    fix.vta.script(
        GROUP_REMOVE_V0_3,
        Script::Refuse("rooms/owner/group/remove:earlierRemovalRefused"),
    );
    let (_, refused) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(
        error_code(&refused),
        Some(REMOVE_KEY_HOLDER_REFUSED),
        "{refused}"
    );
    assert_eq!(
        refused["payload"]["details"]["code"], "rooms/owner/group/remove:earlierRemovalRefused",
        "{refused}"
    );
    let message = refused["payload"]["message"].as_str().unwrap();
    assert!(
        message.contains("did not take effect") && message.contains("Repeat this removal"),
        "{message}"
    );
    assert_eq!(state_in(&fix, &room, &alice.did).await, "admitted");

    let (_, removed) = admin_call(
        &mut fix,
        REMOVE_V0_2,
        json!({ "roomId": room, "member": alice.did, "reason": "left the board" }),
    )
    .await;
    assert_eq!(removed["payload"]["epoch"], 3, "{removed}");
    assert_eq!(state_in(&fix, &room, &alice.did).await, "removed");
}

/// `rooms/owner/group/add/0.3` item 6.1: the VTA gave up an earlier removal from the room
/// it was settling and did nothing of this admission. The member is told nothing was done
/// and to send the same request again — never which member that removal concerned — and
/// nothing is recorded; the repeat proceeds.
#[tokio::test]
async fn an_acceptance_after_an_earlier_removal_the_vta_gave_up_is_refused_and_retried() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "attributed").await;
    let alice = member(&fix).await;
    add_member(&mut fix, &room, &alice.did, &in_a_year()).await;
    fix.vta.script(
        GROUP_ADD,
        Script::Refuse("rooms/owner/group/add:earlierRemovalRefused"),
    );
    let refused = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&refused),
        Some(ACCEPT_KEY_HOLDER_REFUSED),
        "{refused}"
    );
    assert_eq!(
        refused["payload"]["details"]["code"], "rooms/owner/group/add:earlierRemovalRefused",
        "{refused}"
    );
    let message = refused["payload"]["message"].as_str().unwrap();
    assert!(
        message.contains("nothing was done") && message.contains("send the same request again"),
        "{message}"
    );
    assert!(
        !refused.to_string().contains("refused by the stand-in"),
        "the VTA's own message is the administrators', not the member's: {refused}"
    );
    assert_eq!(fix.vta.group(&room).unwrap().1, 1, "nothing was admitted");

    let accepted = call_as(
        &fix,
        &alice,
        ACCEPT,
        json!({ "roomId": room, "keyPackage": "S1A" }),
    )
    .await;
    assert_eq!(accepted["payload"]["state"], "admitted", "{accepted}");
    assert_eq!(accepted["payload"]["epoch"], 2, "{accepted}");
}

// ─── a group's room bindings (`vtc/groups/bindings/*`) ──────────────────

const BINDINGS_ADD: &str = "https://trusttasks.org/spec/vtc/groups/bindings/add/0.1";
const BINDINGS_REMOVE: &str = "https://trusttasks.org/spec/vtc/groups/bindings/remove/0.1";
const BINDINGS_LIST: &str = "https://trusttasks.org/spec/vtc/groups/bindings/list/0.1";
const OFFERS_V0_3: &str = "https://trusttasks.org/spec/vtc/rooms/offers/list/0.3";
const BINDINGS_ADD_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::add::v0_1::error_codes::NOT_FOUND.code;
const BINDINGS_ADD_ERR_ROOM_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::add::v0_1::error_codes::ROOM_NOT_FOUND.code;
const BINDINGS_ADD_ERR_BINDING_EXISTS: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::add::v0_1::error_codes::BINDING_EXISTS.code;
const BINDINGS_ADD_ERR_TOO_MANY_BINDINGS: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::add::v0_1::error_codes::TOO_MANY_BINDINGS.code;
const BINDINGS_REMOVE_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::remove::v0_1::error_codes::NOT_FOUND.code;
const BINDINGS_REMOVE_ERR_BINDING_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::remove::v0_1::error_codes::BINDING_NOT_FOUND.code;
const BINDINGS_LIST_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::groups::bindings::list::v0_1::error_codes::NOT_FOUND.code;

/// A closed static group stored directly, with `members` in it.
async fn a_group_with(fix: &Fixture, members: &[&Party]) -> String {
    use vtc_service::groups;
    let ks = fix.vtc.state.directory.ks();
    let group_id = format!("grp_{}", &uuid::Uuid::new_v4().simple().to_string()[..22]);
    let group: groups::Group = serde_json::from_value(json!({
        "groupId": group_id,
        "groupDid": format!("did:webvh:Qm{group_id}:groups.example"),
        "signingKeyId": "key-1",
        "name": "Board",
        "joinPolicy": "closed",
        "visibility": "members",
        "showMembers": "members",
        "issuesCredentials": false,
        "createdAt": "2026-10-20T00:00:00Z",
        "updatedAt": "2026-10-20T00:00:00Z",
    }))
    .unwrap();
    groups::put(ks, &group).await.unwrap();
    for m in members {
        join_group(fix, &group_id, m).await;
    }
    group_id
}

async fn join_group(fix: &Fixture, group_id: &str, who: &Party) {
    let ks = fix.vtc.state.directory.ks();
    let card = vtc_service::directory::cards::ensure(
        ks,
        &who.did,
        &fix.vtc.state.directory.settings(),
        None,
    )
    .await
    .unwrap();
    vtc_service::groups::put_membership(
        ks,
        &vtc_service::groups::Membership {
            group_id: group_id.to_string(),
            entry_id: card.entry_id,
            source: "added".into(),
            since: Utc::now(),
            state: "active".into(),
            credential_id: None,
            credential_valid_until: None,
        },
    )
    .await
    .unwrap();
}

fn room_binding(room: &str) -> Value {
    json!({ "kind": "room", "roomId": room, "actions": ["read"], "validFor": "P30D" })
}

async fn bind(fix: &mut Fixture, group: &str, room: &str) -> Value {
    let (status, reply) = admin_call(
        fix,
        BINDINGS_ADD,
        json!({ "groupId": group, "binding": room_binding(room), "reason": "the board's room" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["payload"]["binding"].clone()
}

async fn reconcile(fix: &Fixture) -> vtc_service::groups::bindings::Report {
    vtc_service::groups::bindings::reconcile(&fix.vtc.state, Utc::now())
        .await
        .unwrap()
}

/// A room binding offers every member of the group admission; they accept as from any
/// offer; before their authority lapses the community renews it into
/// `offers/list/0.3`'s `renewals`; and leaving the group owes their removal.
#[tokio::test]
async fn a_room_binding_admits_renews_and_withdraws_a_groups_members() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "open").await;
    let alice = member(&fix).await;
    let group = a_group_with(&fix, &[&alice]).await;

    let binding = bind(&mut fix, &group, &room).await;
    assert_eq!(binding["state"], "active");
    let id = binding["bindingId"].as_str().unwrap().to_string();

    let report = reconcile(&fix).await;
    assert_eq!(report.offered, vec![(room.clone(), alice.did.clone())]);
    assert!(reconcile(&fix).await.offered.is_empty(), "offered once");

    let offers = call_as(&fix, &alice, OFFERS_V0_3, json!({})).await;
    assert_eq!(
        offers["payload"]["items"][0]["roomId"],
        room.as_str(),
        "{offers}"
    );
    assert!(offers["payload"].get("renewals").is_none());
    let accepted = call_as(&fix, &alice, ACCEPT, json!({ "roomId": room })).await;
    assert_eq!(accepted["payload"]["state"], "admitted", "{accepted}");

    // Due: within a third of 30 days of the expiry.
    let rooms = &fix.vtc.state.community_rooms;
    let mut record = rooms.member(&room, &alice.did).await.unwrap().unwrap();
    assert_eq!(record.sources, vec![id.clone()]);
    let old_until =
        (Utc::now() + chrono::Duration::days(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    record.valid_until = old_until.clone();
    rooms.put_member(&record).await.unwrap();
    fix.vta.clear_calls();
    let report = reconcile(&fix).await;
    assert_eq!(report.renewed, vec![(room.clone(), alice.did.clone())]);
    assert_eq!(
        fix.vta.types_called(),
        vec![ISSUE_MEMBERSHIP.to_string(), ISSUE_AUTHORITY.to_string()],
        "a renewal is a membership and an authority, never an invitation"
    );
    let offers = call_as(&fix, &alice, OFFERS_V0_3, json!({})).await;
    let renewal = &offers["payload"]["renewals"][0];
    assert_eq!(renewal["roomId"], room.as_str(), "{offers}");
    assert_eq!(renewal["renews"], old_until.as_str());
    assert!(renewal["credentials"]["authority"].is_string());
    assert!(renewal["credentials"].get("invitation").is_none());
    let record = rooms.member(&room, &alice.did).await.unwrap().unwrap();
    assert_eq!(
        record.valid_until,
        renewal["validUntil"].as_str().unwrap(),
        "the renewed expiry is the admission's own"
    );
    // 0.2 never shows a renewal.
    let older = call_as(&fix, &alice, OFFERS_V0_2, json!({})).await;
    assert!(older["payload"].get("renewals").is_none());

    // Leaving the group: nothing else covers her, so her removal is owed.
    vtc_service::groups::remove_membership(
        fix.vtc.state.directory.ks(),
        &group,
        &vtc_service::directory::cards::entry_of(fix.vtc.state.directory.ks(), &alice.did)
            .await
            .unwrap()
            .unwrap(),
    )
    .await
    .unwrap();
    let report = reconcile(&fix).await;
    assert_eq!(report.withdrawn, vec![(room.clone(), alice.did.clone())]);
    assert!(
        rooms
            .pending_removal(&room, &alice.did)
            .await
            .unwrap()
            .is_some()
    );
}

/// An administrator's direct admission is a source of its own: a binding that also
/// covers the member never removes them when they leave the group.
#[tokio::test]
async fn a_direct_admission_outlives_the_binding_that_also_covered_it() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "open").await;
    let bob = member(&fix).await;
    let added = add_member(&mut fix, &room, &bob.did, &in_a_year()).await;
    assert_eq!(added["payload"]["member"]["state"], "offered", "{added}");
    let group = a_group_with(&fix, &[&bob]).await;
    let id = bind(&mut fix, &group, &room).await["bindingId"]
        .as_str()
        .unwrap()
        .to_string();
    let report = reconcile(&fix).await;
    assert!(report.offered.is_empty());
    assert_eq!(report.covered, vec![(room.clone(), bob.did.clone())]);
    assert_eq!(
        fix.vtc
            .state
            .community_rooms
            .member(&room, &bob.did)
            .await
            .unwrap()
            .unwrap()
            .sources,
        vec!["direct".to_string(), id.clone()]
    );

    // The binding goes: it named an admission, so it is removed through the reconciler.
    let (status, removed) = admin_call(
        &mut fix,
        BINDINGS_REMOVE,
        json!({ "groupId": group, "bindingId": id, "reason": "the board moved" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["payload"]["state"], "removing");
    let report = reconcile(&fix).await;
    assert!(report.withdrawn.is_empty(), "the direct admission stands");
    assert_eq!(report.deleted, vec![id]);
    let record = fix
        .vtc
        .state
        .community_rooms
        .member(&room, &bob.did)
        .await
        .unwrap()
        .unwrap();
    assert!(record.sources.is_empty() && record.state == "offered");
}

#[tokio::test]
async fn vtc_groups_bindings_add_refuses_what_its_specification_declares() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "open").await;
    let group = a_group_with(&fix, &[]).await;
    let add = |group: &str, binding: Value| json!({ "groupId": group, "binding": binding, "reason": "why" });

    let (_, doc) = admin_call(
        &mut fix,
        BINDINGS_ADD,
        add("grp_NoSuchGroupNoSuchGrp", room_binding(&room)),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_ADD_ERR_NOT_FOUND),
        "{doc}"
    );

    let (_, doc) = admin_call(
        &mut fix,
        BINDINGS_ADD,
        add(
            &group,
            room_binding("did:webvh:QmNoSuchRoom:rooms.example:x"),
        ),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_ADD_ERR_ROOM_NOT_FOUND),
        "{doc}"
    );

    bind(&mut fix, &group, &room).await;
    let (_, doc) = admin_call(&mut fix, BINDINGS_ADD, add(&group, room_binding(&room))).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_ADD_ERR_BINDING_EXISTS),
        "{doc}"
    );

    let ks = fix.vtc.state.directory.ks();
    for n in 1..vtc_service::groups::bindings::MAX_BINDINGS {
        let mut spec = room_binding(&room);
        spec["validFor"] = json!(format!("P{n}D"));
        vtc_service::groups::bindings::put(
            ks,
            &vtc_service::groups::bindings::Binding {
                binding_id: vtc_service::groups::bindings::new_binding_id(),
                group_id: group.clone(),
                binding: spec,
                state: "active".into(),
                created_at: Utc::now(),
                created_by: fix.admin.did.clone(),
                reason: "filler".into(),
                delegated_by: None,
            },
        )
        .await
        .unwrap();
    }
    let mut spec = room_binding(&room);
    spec["validFor"] = json!("P999D");
    let (_, doc) = admin_call(&mut fix, BINDINGS_ADD, add(&group, spec)).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_ADD_ERR_TOO_MANY_BINDINGS),
        "{doc}"
    );
}

#[tokio::test]
async fn vtc_groups_bindings_remove_refuses_what_its_specification_declares() {
    let mut fix = fixture().await;
    let group = a_group_with(&fix, &[]).await;
    let (_, doc) = admin_call(
        &mut fix,
        BINDINGS_REMOVE,
        json!({ "groupId": "grp_NoSuchGroupNoSuchGrp", "bindingId": "gb_NoSuchBindingNoSuchBi", "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_REMOVE_ERR_NOT_FOUND),
        "{doc}"
    );
    let (_, doc) = admin_call(
        &mut fix,
        BINDINGS_REMOVE,
        json!({ "groupId": group, "bindingId": "gb_NoSuchBindingNoSuchBi", "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_REMOVE_ERR_BINDING_NOT_FOUND),
        "{doc}"
    );

    // One that covered nobody goes at once.
    let room = create_room(&mut fix, "open").await;
    let id = bind(&mut fix, &group, &room).await["bindingId"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, doc) = admin_call(
        &mut fix,
        BINDINGS_REMOVE,
        json!({ "groupId": group, "bindingId": id, "reason": "x" }),
    )
    .await;
    assert_eq!(doc["payload"]["state"], "removed", "{doc}");
}

#[tokio::test]
async fn vtc_groups_bindings_list_refuses_what_its_specification_declares() {
    let mut fix = fixture().await;
    let room = create_room(&mut fix, "open").await;
    let group = a_group_with(&fix, &[]).await;
    bind(&mut fix, &group, &room).await;
    let (_, listed) = admin_call(&mut fix, BINDINGS_LIST, json!({ "groupId": group })).await;
    assert_eq!(
        listed["payload"]["items"][0]["binding"]["roomId"],
        room.as_str(),
        "{listed}"
    );

    // A member who manages nothing: notFound, as for a group that does not exist.
    let carol = member(&fix).await;
    let doc = call_as(&fix, &carol, BINDINGS_LIST, json!({ "groupId": group })).await;
    assert_eq!(
        tt_error_code(&doc),
        Some(BINDINGS_LIST_ERR_NOT_FOUND),
        "{doc}"
    );
}
