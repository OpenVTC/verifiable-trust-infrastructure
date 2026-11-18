//! `rooms/keys/profile/{read,write}/0.1` and the epoch-advance re-write, end to end against a
//! **real** room host (`room_host::dispatch`) on a loopback port: the same proof
//! verification, chain authorization, version assignment and author recording a host
//! applies, so "the host stored it under `write`" and "the host refused it" are the host's
//! statements, not this test's. The host's answers are signed as its own DID, which this
//! agent requires of every reply it acts on.

use std::sync::Arc;

use chrono::{Duration as Span, Utc};
use dtg_credentials::DTGCredential;
use serde_json::{Value, json};
use trust_tasks_rs::{TrustTask, TypeUri};
use vti_rooms_dtg::test_support::Party;

use super::*;
use crate::operations::room_groups::Member;
use crate::operations::room_oracle::{AUTHORITY_TYPE, MEMBERSHIP_TYPE};

const READ: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_PROFILE_READ_0_1;
const WRITE: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_PROFILE_WRITE_0_1;
const OWNER_KEY_PATH: &str = "m/44'/0'/7'/0'/1'";
const ROOM_KEY_PATH: &str = "m/44'/0'/7'/0'/2'";
const MEMBER_KEY_PATH: &str = "m/44'/0'/7'/0'/3'";

/// A real room host behind HTTP, its answers signed as its DID.
struct Host {
    did: String,
    state: Arc<room_host::HostState>,
    doc: Value,
    /// The type of every document the host received, in order.
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
}

impl Host {
    /// How many documents of `task` the host received.
    fn received(&self, task: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.as_str() == task)
            .count()
    }
}

async fn start_host() -> Host {
    start_host_with(false).await
}

async fn start_host_with(contend: bool) -> Host {
    start_host_opts(contend, false).await
}

/// [`start_host`]; with `contend`, every `rooms/records/put` loses its predicted version to
/// another write that lands just before it — the version race `rooms/keys/profile/write`
/// item 6 answers `contended` for when it never stops. With `predates_v3`, the host answers
/// `rooms/records/get/0.3` and `rooms/records/list/0.6` `unsupportedType`, as a host from
/// before them does.
async fn start_host_opts(contend: bool, predates_v3: bool) -> Host {
    // A host predating get/0.3 predates get/0.4 as well.
    const PREDATES_V3: &[&str] = &[
        vti_rooms::wire::ROOMS_RECORDS_GET_V3_TYPE,
        vti_rooms::wire::ROOMS_RECORDS_GET_V4_TYPE,
        vti_rooms::wire::ROOMS_RECORDS_LIST_V6_TYPE,
    ];
    start_host_refusing(contend, if predates_v3 { PREDATES_V3 } else { &[] }).await
}

/// [`start_host_opts`], the host answering `unsupportedType` to every task in `refused`.
async fn start_host_refusing(contend: bool, refused: &'static [&'static str]) -> Host {
    let party = Party::new();
    let dir = tempfile::tempdir().unwrap();
    let state = room_host::open_state(dir.path()).expect("a host");
    // Owners here are minted per test, and register their rooms on this host.
    state.set_room_creation(room_host::creation::RoomCreation::any_creator());
    state.set_host_did(&party.did).expect("bind the host DID");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = state.clone();
    let host_did = party.did.clone();
    let secret = party.secret_multibase.clone();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let app = axum::Router::new().route(
        "/trust-tasks",
        axum::routing::post(move |body: axum::body::Bytes| {
            let shared = shared.clone();
            let host_did = host_did.clone();
            let secret = secret.clone();
            let log = log.clone();
            async move {
                let received: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let task = received["type"].as_str().unwrap_or_default().to_string();
                log.lock().unwrap().push(task.clone());
                if refused.contains(&task.as_str()) {
                    let doc: TrustTask<Value> = serde_json::from_value(received).unwrap();
                    let refused = doc.reject_with(
                        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                        trust_tasks_rs::RejectReason::UnsupportedType { type_uri: task },
                    );
                    return (
                        axum::http::StatusCode::OK,
                        serde_json::to_string(&refused).unwrap(),
                    );
                }
                if contend {
                    let doc: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    if doc["type"] == vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE
                        && let Some(room) = doc["payload"]["roomId"].as_str()
                    {
                        let noise = vti_rooms::Record {
                            key: format!("noise-{}", uuid::Uuid::new_v4().simple()),
                            version: 0,
                            epoch: None,
                            status: vti_rooms::RecordStatus::Active,
                            pinned: false,
                            sealed: None,
                            nonce: None,
                            sealed_version: None,
                            cleartext: Some(json!({ "body": "another member's write" })),
                            author: None,
                            updated_at: 0,
                            created_at: None,
                            created_by: None,
                            body_stored_at: None,
                        };
                        vti_rooms::storage::put_record(
                            shared.rooms(),
                            shared.records(),
                            room,
                            noise,
                            None,
                            Utc::now().timestamp() as u64,
                        )
                        .await
                        .expect("the competing write lands");
                    }
                }
                let answer = room_host::dispatch(&shared, &body).await;
                let mut doc = answer.document;
                if doc["type"]
                    .as_str()
                    .is_some_and(|t| t.ends_with("#response"))
                {
                    let mut typed: TrustTask<Value> = serde_json::from_value(doc).unwrap();
                    vta_sdk::trust_task_sign::sign_in_place(&mut typed, &host_did, &secret)
                        .await
                        .unwrap();
                    doc = serde_json::to_value(typed).unwrap();
                }
                (axum::http::StatusCode::OK, doc.to_string())
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mb = party.did.strip_prefix("did:key:").unwrap();
    let vm = format!("{}#{mb}", party.did);
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": party.did,
        "verificationMethod": [{
            "id": vm, "type": "Multikey", "controller": party.did, "publicKeyMultibase": mb,
        }],
        "authentication": [vm],
        "assertionMethod": [vm],
        "service": [{
            "id": format!("{}#rest", party.did), "type": "TrustTaskHTTPS",
            "serviceEndpoint": format!("http://127.0.0.1:{port}"),
        }],
    });
    Host {
        did: party.did,
        state,
        doc,
        seen,
        _dir: dir,
    }
}

/// One member's VTA: their persona, the room's grant to it and its membership in the vault,
/// and a resolver that knows the host.
struct Vta {
    state: AppState,
    _dir: tempfile::TempDir,
    persona: String,
}

async fn vta(room: &Party, host: &Host, key_path: &str, actions: &[&str]) -> Vta {
    let (mut state, dir) = crate::test_support::build_signing_test_app_state().await;
    let persona = crate::test_support::seed_holder_key(&state, key_path, None).await;
    let now = Utc::now();
    let mut vac = DTGCredential::new_vac(
        room.did.clone(),
        dtg_credentials::IssuerScope::Public,
        persona.clone(),
        room.did.clone(),
        actions.iter().map(|a| a.to_string()).collect(),
        now - Span::minutes(1),
        now + Span::days(30),
    )
    .unwrap()
    .with_id(format!("urn:example:vac:{persona}"));
    vac.sign(&room.secret, None).await.unwrap();
    let mut vmc = DTGCredential::new_vmc(
        room.did.clone(),
        persona.clone(),
        now - Span::minutes(1),
        Some(now + Span::days(30)),
        false,
    );
    vmc.sign(&room.secret, None).await.unwrap();
    vault(&state, AUTHORITY_TYPE, &room.did, &vac).await;
    vault(&state, MEMBERSHIP_TYPE, &room.did, &vmc).await;

    let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    .unwrap();
    resolver
        .add_did_document(&host.did, serde_json::from_value(host.doc.clone()).unwrap())
        .await;
    state.did_resolver = Some(resolver);
    Vta {
        state,
        _dir: dir,
        persona,
    }
}

async fn vault(state: &AppState, type_tag: &str, issuer: &str, cred: &DTGCredential) {
    use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
    use vti_common::vault::VaultStatus;
    crate::vault::storage::put(
        &state.vault_ks,
        &StoredCredential {
            id: format!("{type_tag}-{issuer}"),
            format: CredentialFormat::EddsaJcs2022,
            types: vec![type_tag.into()],
            schema_id: None,
            community_did: None,
            context_id: None,
            subject_did: None,
            issuer_did: Some(issuer.to_string()),
            purpose: None,
            status: CredentialStatus::Unknown,
            valid_from: None,
            valid_until: None,
            received_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            tags: Default::default(),
            body: serde_json::to_vec(cred).unwrap(),
            lifecycle: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        },
    )
    .await
    .unwrap();
}

async fn seed_room(host: &Host, room: &str, owner: &str, visibility: vti_rooms::Visibility) {
    vti_rooms::storage::create_room(
        host.state.rooms(),
        &vti_rooms::Room {
            room_id: room.to_string(),
            owner_did: owner.to_string(),
            visibility,
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
            signal_delay: Default::default(),
            epoch_floor: None,
            frozen_at: None,
        },
    )
    .await
    .expect("seed the room");
}

fn request(uri: &str, payload: Value) -> TrustTask<Value> {
    let uri: TypeUri = uri.parse().unwrap();
    TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
}

fn body(outcome: TrustTaskOutcome) -> Value {
    serde_json::from_slice(&outcome.body).expect("a document")
}

fn admin() -> AuthClaims {
    crate::test_support::super_admin_claims()
}

async fn read(v: &Vta, room: &str, host: &Host) -> Value {
    body(
        handle_read(
            &v.state,
            &admin(),
            request(READ, json!({ "roomId": room, "host": host.did })),
        )
        .await,
    )
}

async fn write_profile(v: &Vta, room: &str, host: &Host, profile: Value) -> Value {
    body(
        handle_write(
            &v.state,
            &admin(),
            request(
                WRITE,
                json!({ "roomId": room, "host": host.did, "profile": profile }),
            ),
        )
        .await,
    )
}

/// A sealed room, its owner holding every action and the room's group, at epoch 1.
struct Sealed {
    host: Host,
    room: Party,
    owner: Vta,
}

async fn sealed_room() -> Sealed {
    sealed_room_on(start_host().await).await
}

/// [`sealed_room`], on `host`.
async fn sealed_room_on(host: Host) -> Sealed {
    let room = Party::new();
    let owner = vta(
        &room,
        &host,
        OWNER_KEY_PATH,
        &["read", "write", "curate", "admin"],
    )
    .await;
    seed_room(
        &host,
        &room.did,
        &owner.persona,
        vti_rooms::Visibility::Attributed,
    )
    .await;
    let room_signing =
        crate::test_support::seed_holder_key(&owner.state, ROOM_KEY_PATH, None).await;
    let room_key = format!(
        "{room_signing}#{}",
        room_signing.strip_prefix("did:key:").unwrap()
    );
    let created = body(
        super::super::room_owner_group::handle_create(
            &owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_CREATE_0_1,
                json!({ "roomId": room.did, "signingKeyId": room_key, "member": owner.persona }),
            ),
        )
        .await,
    );
    assert_eq!(created["payload"]["epoch"], 1, "{created}");
    Sealed { host, room, owner }
}

/// Admit a member holding `actions` with their own VTA, through the owner's
/// `rooms/owner/group/add/0.3` at the real host; the member joins from the Welcome.
async fn admit(s: &Sealed, actions: &[&str]) -> Vta {
    admit_at(s, MEMBER_KEY_PATH, actions).await
}

/// [`admit`], the member's persona at `key_path` — so a room can take a second member.
async fn admit_at(s: &Sealed, key_path: &str, actions: &[&str]) -> Vta {
    let m = vta(&s.room, &s.host, key_path, actions).await;
    let kp = room_groups::mint_key_package(
        &m.state.room_groups_ks,
        &Member::new(&s.room.did, &m.persona).unwrap(),
        3600,
        0,
    )
    .await
    .unwrap();
    let out = body(
        super::super::room_owner_group::handle_add_v0_3(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_3,
                json!({
                    "roomId": s.room.did, "host": s.host.did, "member": m.persona,
                    "keyPackage": kp.key_package,
                }),
            ),
        )
        .await,
    );
    let welcome = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                out["payload"]["welcome"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{out}")),
            )
            .unwrap()
    };
    room_groups::join(
        &m.state.room_groups_ks,
        &Member::new(&s.room.did, &m.persona).unwrap(),
        &welcome,
        0,
    )
    .await
    .expect("joins from the Welcome");
    m
}

fn board() -> Value {
    json!({
        "name": "Board pack — 2027",
        "description": "Papers for the 2027 board meetings.",
        "tags": ["board", "finance"],
        "emoji": "📋",
    })
}

/// Written as the owner, read back as the owner: sealed at the host under an opaque key
/// derived from the epoch's storage key, which says nothing in the clear.
#[tokio::test]
async fn a_curators_profile_is_written_sealed_and_read_back() {
    let s = sealed_room().await;
    let out = write_profile(&s.owner, &s.room.did, &s.host, board()).await;
    assert_eq!(out["payload"]["outcome"], "written", "{out}");
    assert_eq!(out["payload"]["epoch"], 1, "{out}");
    let key = out["payload"]["key"].as_str().unwrap().to_string();
    assert_eq!(key.len(), 22, "the shape of any random record key");

    // At the host: ciphertext, at that key, attributed to the owner persona.
    let stored = vti_rooms::storage::get_record(s.host.state.records(), &s.room.did, &key)
        .await
        .expect("stored");
    assert_eq!(stored.author.as_deref(), Some(s.owner.persona.as_str()));
    let at_host = serde_json::to_string(&stored).unwrap();
    assert!(
        !at_host.contains("Board pack"),
        "the name never reaches the host"
    );

    let got = read(&s.owner, &s.room.did, &s.host).await;
    let p = &got["payload"];
    assert_eq!(p["status"], "found", "{got}");
    assert_eq!(p["profile"], board());
    assert_eq!(p["author"], s.owner.persona);
    assert_eq!(p["epoch"], 1);
    assert_eq!(p["stale"], false);
    assert_eq!(p["searched"], json!({ "fromEpoch": 1, "toEpoch": 1 }));
    assert!(p.get("rejected").is_none(), "{got}");
    assert!(p["verification"]["trace"].is_string(), "{got}");
}

/// A room with no profile reads `absent`, and says how far it looked.
#[tokio::test]
async fn a_room_with_no_profile_is_absent() {
    let s = sealed_room().await;
    let got = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(got["payload"]["status"], "absent", "{got}");
    assert_eq!(
        got["payload"]["searched"],
        json!({ "fromEpoch": 1, "toEpoch": 1 })
    );
}

/// **The forged rename.** A member holding only `write` is refused by their own VTA before
/// the host is contacted — and when they go round it, signing a statement themselves and
/// storing it at the profile location (which the host must accept: it cannot tell the
/// record is the profile), every reader ignores it as `noAuthority`, names them, and keeps
/// the profile before it.
#[tokio::test]
async fn a_write_only_members_rename_is_refused_and_then_ignored() {
    let s = sealed_room().await;
    write_profile(&s.owner, &s.room.did, &s.host, board()).await;
    let mallory = admit(&s, &["read", "write"]).await;

    // The owner re-wrote the profile under epoch 2 at the admission, so the newcomer —
    // who reads only from the epoch they joined at — sees it.
    let seen = read(&mallory, &s.room.did, &s.host).await;
    assert_eq!(seen["payload"]["status"], "found", "{seen}");
    assert_eq!(seen["payload"]["epoch"], 2, "{seen}");
    assert_eq!(seen["payload"]["author"], s.owner.persona);

    // Through the task: refused, before the host.
    let refused = write_profile(
        &mallory,
        &s.room.did,
        &s.host,
        json!({ "name": "Mallory's" }),
    )
    .await;
    assert_eq!(
        refused["payload"]["code"], "rooms/keys/profile/write:noAuthority",
        "{refused}"
    );

    // Around it: the same statement a hostile client would build.
    let resolver = mallory.state.did_resolver.clone().unwrap();
    let auth = admin();
    let sp = Speaker::for_caller(
        &mallory.state,
        &auth,
        &resolver,
        &s.room.did,
        &s.host.did,
        None,
    )
    .await
    .unwrap();
    let forged = write(&sp, true, &json!({ "name": "Mallory's room" }))
        .await
        .expect("the host stores what `write` permits");
    assert_eq!(forged.epoch, Some(2));

    // The owner: epoch 2's record ignored, epoch 1's profile still the room's, stale.
    let got = read(&s.owner, &s.room.did, &s.host).await;
    let p = &got["payload"];
    assert_eq!(p["status"], "found", "{got}");
    assert_eq!(p["profile"]["name"], "Board pack — 2027");
    assert_eq!(p["epoch"], 1);
    assert_eq!(p["stale"], true);
    assert_eq!(p["searched"], json!({ "fromEpoch": 2, "toEpoch": 1 }));
    assert_eq!(
        p["rejected"],
        json!([{ "epoch": 2, "version": forged.version, "reason": "noAuthority", "author": mallory.persona }])
    );

    // Mallory herself cannot walk below the epoch she joined at: absent, and told why.
    let theirs = read(&mallory, &s.room.did, &s.host).await;
    assert_eq!(theirs["payload"]["status"], "absent", "{theirs}");
    assert_eq!(theirs["payload"]["rejected"][0]["reason"], "noAuthority");

    // The owner repairs it by writing again.
    write_profile(&s.owner, &s.room.did, &s.host, board()).await;
    let fixed = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(fixed["payload"]["epoch"], 2, "{fixed}");
    assert_eq!(fixed["payload"]["stale"], false);
    assert!(fixed["payload"].get("rejected").is_none(), "{fixed}");
}

/// Every advance re-writes the profile under the new epoch, as the owner: a renewal moves it
/// from a stale epoch to the current one. A room with no profile gets none.
#[tokio::test]
async fn an_advance_re_writes_the_profile_under_the_new_epoch() {
    let s = sealed_room().await;
    let renew = |s: &Sealed| {
        let doc = request(
            vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_RENEW_0_2,
            json!({ "roomId": s.room.did, "host": s.host.did }),
        );
        let state = s.owner.state.clone();
        async move {
            body(super::super::room_owner_group::handle_renew_v0_2(&state, &admin(), doc).await)
        }
    };

    // No profile: the advance writes none on the room's behalf (item 4).
    let out = renew(&s).await;
    assert_eq!(out["payload"]["epoch"], 2, "{out}");
    assert_eq!(
        read(&s.owner, &s.room.did, &s.host).await["payload"]["status"],
        "absent"
    );

    write_profile(&s.owner, &s.room.did, &s.host, board()).await;
    let out = renew(&s).await;
    assert_eq!(out["payload"]["epoch"], 3, "{out}");
    let got = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(got["payload"]["status"], "found", "{got}");
    assert_eq!(got["payload"]["epoch"], 3);
    assert_eq!(got["payload"]["stale"], false);
    assert_eq!(got["payload"]["profile"], board());
}

/// **`recordMembers` survives every advance.** The owner's key holder re-writes the profile
/// under the epoch each advance moves to, and must carry `recordMembers` through unchanged
/// (`RoomProfile.recordMembers`, *Turning them on*, step 2): one that dropped it would
/// silently turn the room's record members off at the next removal. An admission and a
/// renewal here; a removal takes the same read-before and re-write-after
/// (`room_owner_group::handle_remove_v0_4`), which this fixture cannot drive — its room's
/// signing key is not the room DID's, so the host refuses the withdrawal a removal sends.
#[tokio::test]
async fn an_advance_carries_record_members_into_the_new_epoch() {
    let s = sealed_room().await;
    let profile = json!({
        "name": "Deal room",
        "recordMembers": ["kind", "inReplyTo", "writtenAt", "editedAt", "width", "height",
                          "preview"],
    });
    write_profile(&s.owner, &s.room.did, &s.host, profile.clone()).await;
    let before = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(before["payload"]["profile"], profile, "{before}");
    assert_eq!(before["payload"]["epoch"], 1, "{before}");

    // An admission advances the room to epoch 2.
    let _member = admit(&s, &["read", "write"]).await;
    let admitted = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(admitted["payload"]["epoch"], 2, "{admitted}");
    assert_eq!(
        admitted["payload"]["stale"], false,
        "re-written under epoch 2"
    );
    assert_eq!(
        admitted["payload"]["profile"], profile,
        "carried through the admission"
    );

    // A renewal to epoch 3.
    let renewed = body(
        super::super::room_owner_group::handle_renew_v0_2(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_RENEW_0_2,
                json!({ "roomId": s.room.did, "host": s.host.did }),
            ),
        )
        .await,
    );
    assert_eq!(renewed["payload"]["epoch"], 3, "{renewed}");
    let after = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(after["payload"]["status"], "found", "{after}");
    assert_eq!(after["payload"]["epoch"], 3);
    assert_eq!(after["payload"]["stale"], false, "re-written under epoch 3");
    assert_eq!(
        after["payload"]["profile"], profile,
        "recordMembers carried through unchanged"
    );
}

/// Clearing retracts the current epoch's record (curate at the host), and the walk stops
/// there: `cleared`, not the older profile below it. An advance after a clear writes none.
#[tokio::test]
async fn clearing_stops_the_walk() {
    let s = sealed_room().await;
    write_profile(&s.owner, &s.room.did, &s.host, board()).await;
    // Advance, so the current epoch's location is the re-written one.
    let _ = admit(&s, &["read"]).await;

    let out = body(
        handle_write(
            &s.owner.state,
            &admin(),
            request(
                WRITE,
                json!({ "roomId": s.room.did, "host": s.host.did, "clear": true }),
            ),
        )
        .await,
    );
    assert_eq!(out["payload"]["outcome"], "cleared", "{out}");
    let got = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(got["payload"]["status"], "cleared", "{got}");
    assert_eq!(got["payload"]["epoch"], 2);
    assert!(got["payload"].get("profile").is_none());

    // Reversible by another write, at the same epoch.
    let again = write_profile(&s.owner, &s.room.did, &s.host, json!({ "name": "Board" })).await;
    assert_eq!(again["payload"]["outcome"], "written", "{again}");
    let got = read(&s.owner, &s.room.did, &s.host).await;
    assert_eq!(got["payload"]["status"], "found", "{got}");
    assert_eq!(got["payload"]["profile"], json!({ "name": "Board" }));
}

/// A member who holds no curate is refused a clear.
#[tokio::test]
async fn clearing_takes_curate() {
    let s = sealed_room().await;
    let member = admit(&s, &["read", "write"]).await;
    let out = body(
        handle_write(
            &member.state,
            &admin(),
            request(
                WRITE,
                json!({ "roomId": s.room.did, "host": s.host.did, "clear": true }),
            ),
        )
        .await,
    );
    assert_eq!(
        out["payload"]["code"], "rooms/keys/profile/write:noAuthority",
        "{out}"
    );
}

/// A room this VTA holds nothing for is `notAMember`, for both tasks.
#[tokio::test]
async fn a_room_nobody_here_belongs_to_is_not_a_member() {
    let s = sealed_room().await;
    let stranger = Party::new().did;
    let got = body(
        handle_read(
            &s.owner.state,
            &admin(),
            request(READ, json!({ "roomId": stranger, "host": s.host.did })),
        )
        .await,
    );
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/read:notAMember",
        "{got}"
    );
    let got = write_profile(&s.owner, &stranger, &s.host, board()).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/write:notAMember",
        "{got}"
    );
}

/// The profile is not one of the room's records: `rooms/keys/browse` leaves it out (its
/// count still checked against everything the host listed), and `rooms/keys/read` of its
/// key does not open it but says where to read it.
#[tokio::test]
async fn browse_and_read_keep_the_profile_out_of_the_records() {
    let s = sealed_room().await;
    let w = write_profile(&s.owner, &s.room.did, &s.host, board()).await;
    let key = w["payload"]["key"].as_str().unwrap().to_string();

    let listed = body(
        super::super::room_group::handle_browse_v0_3(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_3,
                json!({ "roomId": s.room.did, "host": s.host.did }),
            ),
        )
        .await,
    );
    assert_eq!(listed["payload"]["records"], json!([]), "{listed}");
    assert_eq!(
        listed["payload"]["verification"]["count"], "agrees",
        "{listed}"
    );

    let opened = body(
        super::super::room_group::handle_read(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                json!({ "roomId": s.room.did, "host": s.host.did, "key": key }),
            ),
        )
        .await,
    );
    assert!(opened["payload"].get("plaintext").is_none(), "{opened}");
    assert_eq!(
        opened["payload"]["ext"]["org.openvtc.rooms"]["roomProfile"],
        true
    );
}

/// On an `open` room the profile is the record at `room-profile`, its signed body in
/// `cleartext.body` and its name as the title — and a reader verifies it the same way.
#[tokio::test]
async fn an_open_rooms_profile_is_at_room_profile_in_the_clear() {
    let host = start_host().await;
    let room = Party::new();
    let owner = vta(
        &room,
        &host,
        OWNER_KEY_PATH,
        &["read", "write", "curate", "admin"],
    )
    .await;
    seed_room(
        &host,
        &room.did,
        &owner.persona,
        vti_rooms::Visibility::Open,
    )
    .await;

    let out = write_profile(&owner, &room.did, &host, board()).await;
    assert_eq!(out["payload"]["key"], "room-profile", "{out}");
    assert!(out["payload"].get("epoch").is_none(), "{out}");
    let stored = vti_rooms::storage::get_record(host.state.records(), &room.did, "room-profile")
        .await
        .unwrap();
    let stored = serde_json::to_value(&stored).unwrap();
    assert!(
        stored.to_string().contains("Board pack"),
        "an open room hides nothing from its host"
    );

    let got = read(&owner, &room.did, &host).await;
    assert_eq!(got["payload"]["status"], "found", "{got}");
    assert_eq!(got["payload"]["profile"], board());
    assert!(got["payload"].get("searched").is_none(), "{got}");
}

// ─── The declared refusals, each driven ─────────────────────────────────

/// A DID document for a host nobody answers at: a loopback port nothing listens on.
fn unreachable_host() -> (String, Value) {
    let party = Party::new();
    let mb = party.did.strip_prefix("did:key:").unwrap().to_string();
    let vm = format!("{}#{mb}", party.did);
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": party.did,
        "verificationMethod": [{
            "id": vm, "type": "Multikey", "controller": party.did, "publicKeyMultibase": mb,
        }],
        "authentication": [vm],
        "assertionMethod": [vm],
        "service": [{
            "id": format!("{}#rest", party.did), "type": "TrustTaskHTTPS",
            "serviceEndpoint": "http://127.0.0.1:9",
        }],
    });
    (party.did, doc)
}

/// Teach `v`'s resolver another host's DID document.
async fn knows(v: &mut Vta, did: &str, doc: Value) {
    let mut resolver = v.state.did_resolver.clone().unwrap();
    resolver
        .add_did_document(did, serde_json::from_value(doc).unwrap())
        .await;
    v.state.did_resolver = Some(resolver);
}

async fn read_at(v: &Vta, room: &str, host: &str) -> Value {
    body(
        handle_read(
            &v.state,
            &admin(),
            request(READ, json!({ "roomId": room, "host": host })),
        )
        .await,
    )
}

async fn write_at(v: &Vta, room: &str, host: &str) -> Value {
    body(
        handle_write(
            &v.state,
            &admin(),
            request(
                WRITE,
                json!({ "roomId": room, "host": host, "profile": board() }),
            ),
        )
        .await,
    )
}

/// A host that does not answer is `hostUnreachable`, for both tasks — retryable, and
/// nothing is known to have been stored.
#[tokio::test]
async fn a_host_nobody_answers_at_is_host_unreachable() {
    let mut s = sealed_room().await;
    let (dead, doc) = unreachable_host();
    knows(&mut s.owner, &dead, doc).await;

    let got = read_at(&s.owner, &s.room.did, &dead).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/read:hostUnreachable",
        "{got}"
    );
    let got = write_at(&s.owner, &s.room.did, &dead).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/write:hostUnreachable",
        "{got}"
    );
}

/// A host that answers and declines — here one that does not serve the room — is
/// `hostRefused`, its own code and message carried in `details`; and a refusal is not an
/// empty profile location.
#[tokio::test]
async fn a_host_that_does_not_serve_the_room_is_host_refused() {
    let mut s = sealed_room().await;
    let other = start_host().await;
    knows(&mut s.owner, &other.did, other.doc.clone()).await;

    let got = read_at(&s.owner, &s.room.did, &other.did).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/read:hostRefused",
        "{got}"
    );
    assert!(got["payload"]["details"]["code"].is_string(), "{got}");
    let got = write_at(&s.owner, &s.room.did, &other.did).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/write:hostRefused",
        "{got}"
    );
    assert!(got["payload"]["details"]["message"].is_string(), "{got}");
}

/// Item 6: when other writes keep taking the version a profile was sealed for, the write
/// re-seals for the next one a bounded number of times and then answers `contended` —
/// never `written` for a record that does not open.
#[tokio::test]
async fn a_write_that_keeps_losing_its_version_is_contended() {
    let host = start_host_with(true).await;
    let room = Party::new();
    let owner = vta(
        &room,
        &host,
        OWNER_KEY_PATH,
        &["read", "write", "curate", "admin"],
    )
    .await;
    seed_room(
        &host,
        &room.did,
        &owner.persona,
        vti_rooms::Visibility::Open,
    )
    .await;

    let got = write_profile(&owner, &room.did, &host, board()).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/profile/write:contended",
        "{got}"
    );
    // And no reader takes what landed for the profile.
    let read = read(&owner, &room.did, &host).await;
    assert_ne!(read["payload"]["status"], "found", "{read}");
}

// ─── Reading a record across epochs: repair before refusing ─────────────────────────────
//
// `rooms/keys/read/0.1`, *Opening, and when it cannot*: a member behind by a commit, or
// one who joined after a record was written, is repaired from the host before the record
// is refused — and what still will not open is `cannotOpen` with its reason.

const SECOND_MEMBER_KEY_PATH: &str = "m/44'/0'/7'/0'/4'";

/// Put a record the owner sealed under the room's current epoch at the host, as the
/// owner's client would after `rooms/keys/seal`.
async fn owner_writes(s: &Sealed, key: &str, text: &str) {
    let room = vti_rooms::storage::get_room(s.host.state.rooms(), &s.room.did)
        .await
        .unwrap();
    let owner = Member::new(&s.room.did, &s.owner.persona).unwrap();
    let sealed = room_groups::seal_record(
        &s.owner.state.room_groups_ks,
        &owner,
        key,
        room.next_version,
        text.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(sealed.epoch, room.epoch, "sealed under the room's epoch");
    put_sealed(s, key, sealed.epoch, sealed.ciphertext, sealed.nonce).await;
}

async fn put_sealed(s: &Sealed, key: &str, epoch: u32, ciphertext: String, nonce: String) {
    vti_rooms::storage::put_record(
        s.host.state.rooms(),
        s.host.state.records(),
        &s.room.did,
        vti_rooms::Record {
            key: key.to_string(),
            version: 0,
            epoch: Some(epoch),
            status: vti_rooms::RecordStatus::Active,
            pinned: false,
            sealed: Some(ciphertext),
            nonce: Some(nonce),
            sealed_version: None,
            cleartext: None,
            author: Some(s.owner.persona.clone()),
            updated_at: 0,
            created_at: None,
            created_by: None,
            body_stored_at: None,
        },
        Some(0),
        Utc::now().timestamp() as u64,
    )
    .await
    .expect("the host stores the record");
}

async fn read_record(v: &Vta, s: &Sealed, key: &str) -> Value {
    body(
        super::super::room_group::handle_read(
            &v.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                json!({ "roomId": s.room.did, "host": s.host.did, "key": key }),
            ),
        )
        .await,
    )
}

fn plaintext_of(got: &Value) -> String {
    use base64::Engine as _;
    let b64 = got["payload"]["plaintext"]
        .as_str()
        .unwrap_or_else(|| panic!("{got}"));
    String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .unwrap(),
    )
    .unwrap()
}

async fn held(v: &Vta, s: &Sealed) -> room_groups::HeldRoom {
    room_groups::held_room(
        &v.state.room_groups_ks,
        &Member::new(&s.room.did, &v.persona).unwrap(),
    )
    .await
    .unwrap()
}

/// **Behind by a commit.** A second admission moves the room to epoch 3 and leaves the first
/// member at 2; reading what was sealed under 3 applies the commit the host relays, then
/// opens it — no `keys commit` by hand.
#[tokio::test]
async fn a_member_behind_by_a_commit_catches_up_before_opening() {
    let s = sealed_room().await;
    let a = admit(&s, &["read", "write"]).await;
    let _b = admit_at(&s, SECOND_MEMBER_KEY_PATH, &["read"]).await;
    assert_eq!(
        held(&a, &s).await.epoch,
        2,
        "the first member missed the second's commit"
    );

    owner_writes(&s, "rec-after-second-member", "written at epoch 3").await;
    let got = read_record(&a, &s, "rec-after-second-member").await;
    assert_eq!(plaintext_of(&got), "written at epoch 3");
    assert_eq!(
        held(&a, &s).await.epoch,
        3,
        "the commit was applied and kept"
    );
}

/// **Joined late.** A record written before a member joined opens on their first read:
/// their VTA fetches the epoch link from the host, keeps it, and opens.
#[tokio::test]
async fn a_member_who_joined_late_fetches_the_history_before_opening() {
    let s = sealed_room().await;
    owner_writes(&s, "rec-before-joining", "written at epoch 1").await;
    let a = admit(&s, &["read"]).await;
    assert_eq!(held(&a, &s).await.earliest_readable_epoch, 2);

    let got = read_record(&a, &s, "rec-before-joining").await;
    assert_eq!(plaintext_of(&got), "written at epoch 1");
    assert_eq!(
        held(&a, &s).await.earliest_readable_epoch,
        1,
        "the link is kept"
    );
}

/// A page opening many records at once repairs once: every read opens, and the group
/// state each one leaves behind is the same.
#[tokio::test]
async fn concurrent_reads_share_one_repair() {
    let s = sealed_room().await;
    let a = admit(&s, &["read"]).await;
    let _b = admit_at(&s, SECOND_MEMBER_KEY_PATH, &["read"]).await;
    for i in 0..4 {
        owner_writes(&s, &format!("rec-{i}"), &format!("record {i}")).await;
    }
    let reads = (0..4).map(|i| {
        let (a, s) = (&a, &s);
        async move { (i, read_record(a, s, &format!("rec-{i}")).await) }
    });
    for (i, got) in futures_util::future::join_all(reads).await {
        assert_eq!(plaintext_of(&got), format!("record {i}"));
    }
    assert_eq!(held(&a, &s).await.epoch, 3);
}

/// What the host cannot supply is `cannotOpen` — never a malformed request — with the
/// record's epoch, the reason, and why the repair stopped.
#[tokio::test]
async fn a_commit_the_host_never_got_is_cannot_open_not_delivered() {
    let s = sealed_room().await;
    let a = admit(&s, &["read"]).await;
    // The room moves to 3 at the host with no commit relayed for it.
    vti_rooms::storage::advance_epoch(
        s.host.state.rooms(),
        &s.room.did,
        3,
        Utc::now().timestamp() as u64,
    )
    .await
    .unwrap();
    put_sealed(
        &s,
        "rec-unreachable",
        3,
        "AAAA".into(),
        "AAAAAAAAAAAAAAAA".into(),
    )
    .await;

    let got = read_record(&a, &s, "rec-unreachable").await;
    let p = &got["payload"];
    assert_eq!(p["code"], "rooms/keys/read:cannotOpen", "{got}");
    assert_eq!(p["details"]["reason"], "notDelivered", "{got}");
    assert_eq!(p["details"]["heldEpoch"], 2, "{got}");
    assert_eq!(p["details"]["epoch"], 3, "{got}");
    assert!(
        p["message"]
            .as_str()
            .unwrap()
            .contains("no commit producing room epoch 3"),
        "{got}"
    );
    assert_eq!(held(&a, &s).await.epoch, 2, "nothing was applied");
}

/// A host that does not answer is `hostUnreachable` for a record read — retryable, and not
/// a malformed request: the request was fine.
#[tokio::test]
async fn a_record_read_at_a_host_nobody_answers_is_host_unreachable() {
    let mut s = sealed_room().await;
    let (dead, doc) = unreachable_host();
    knows(&mut s.owner, &dead, doc).await;
    let got = body(
        super::super::room_group::handle_read(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                json!({ "roomId": s.room.did, "host": dead, "key": "anything" }),
            ),
        )
        .await,
    );
    assert_eq!(
        got["payload"]["code"], "rooms/keys/read:hostUnreachable",
        "{got}"
    );
}

/// The other host failures, by their declared codes: a host that does not serve the room is
/// `hostRefused` for a record read and for backfill, with its own code in `details`; one
/// nobody answers at is backfill's `hostUnreachable`.
#[tokio::test]
async fn record_read_and_backfill_name_the_host_failure() {
    let mut s = sealed_room().await;
    let other = start_host().await;
    knows(&mut s.owner, &other.did, other.doc.clone()).await;
    let (dead, doc) = unreachable_host();
    knows(&mut s.owner, &dead, doc).await;

    let read = |host: String| {
        let s = &s;
        async move {
            body(
                super::super::room_group::handle_read(
                    &s.owner.state,
                    &admin(),
                    request(
                        vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                        json!({ "roomId": s.room.did, "host": host, "key": "anything" }),
                    ),
                )
                .await,
            )
        }
    };
    let got = read(other.did.clone()).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/read:hostRefused",
        "{got}"
    );
    assert!(got["payload"]["details"]["code"].is_string(), "{got}");

    let backfill = |host: String| {
        let s = &s;
        async move {
            body(
                super::super::room_group::handle_backfill_v0_2(
                    &s.owner.state,
                    &admin(),
                    request(
                        vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BACKFILL_0_2,
                        json!({ "roomId": s.room.did, "host": host }),
                    ),
                )
                .await,
            )
        }
    };
    let got = backfill(other.did.clone()).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/backfill:hostRefused",
        "{got}"
    );
    let got = backfill(dead).await;
    assert_eq!(
        got["payload"]["code"], "rooms/keys/backfill:hostUnreachable",
        "{got}"
    );
}

// ─── `rooms/keys/read/0.2` and `rooms/keys/browse/0.4` (trust-tasks-tf #1027) ───────────
//
// What the host records about each version — `createdAt`, `createdBy`, `bodyStoredAt`, and
// on an `open` room the record's `kind` — passed through exactly as served, with fallback to
// a host that predates `rooms/records/get/0.3` and `rooms/records/list/0.6`; and read/0.2's
// batch form, each key answered on its own.

const READ_0_2: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_2;
const BROWSE_0_4: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_4;
const GET_V3: &str = vti_rooms::wire::ROOMS_RECORDS_GET_V3_TYPE;
const GET_V2: &str = vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE;
const LIST_V6: &str = vti_rooms::wire::ROOMS_RECORDS_LIST_V6_TYPE;
const LIST_V5: &str = vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE;

/// `rooms/keys/read/0.2` with `which` — `{"key": …}` or `{"keys": […]}` — as `v`.
async fn read_v0_2(v: &Vta, room: &str, host: &str, which: Value) -> Value {
    read_v0_2_within(
        v,
        room,
        host,
        which,
        super::super::room_read::Budget::DEFAULT,
    )
    .await
}

async fn read_v0_2_within(
    v: &Vta,
    room: &str,
    host: &str,
    which: Value,
    budget: super::super::room_read::Budget,
) -> Value {
    let mut payload = json!({ "roomId": room, "host": host });
    for (k, val) in which.as_object().unwrap() {
        payload[k] = val.clone();
    }
    body(
        super::super::room_read::read_v0_2_within(
            &v.state,
            &admin(),
            request(READ_0_2, payload),
            budget,
        )
        .await,
    )
}

async fn browse_v0_4(v: &Vta, room: &str, host: &str) -> Value {
    body(
        super::super::room_group::handle_browse_v0_4(
            &v.state,
            &admin(),
            request(BROWSE_0_4, json!({ "roomId": room, "host": host })),
        )
        .await,
    )
}

fn decoded(b64: &Value) -> String {
    use base64::Engine as _;
    String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                b64.as_str()
                    .unwrap_or_else(|| panic!("not base64url: {b64}")),
            )
            .unwrap(),
    )
    .unwrap()
}

/// Write an `open` room's record with `rooms/records/put/0.5`, completed as `v`'s member by
/// `rooms/keys/act/0.11` and handed to the host unaltered — what pnm does.
async fn put_open_v0_5(v: &Vta, room: &str, host: &Host, key: &str, cleartext: Value) -> Value {
    let unsigned = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE,
        "recipient": host.did,
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "roomId": room, "key": key, "cleartext": cleartext },
    });
    let acted = body(
        super::super::room_act::handle_act_v0_11(
            &v.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_11,
                json!({ "document": unsigned }),
            ),
        )
        .await,
    );
    let completed = acted["payload"]["document"].clone();
    assert!(completed.is_object(), "{acted}");
    let answer = room_host::dispatch(&host.state, &serde_json::to_vec(&completed).unwrap()).await;
    let doc = answer.document;
    assert!(
        doc["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("#response")),
        "{doc}"
    );
    doc["payload"].clone()
}

/// An `open` room on `host`, its owner holding every action.
async fn open_room_on(host: &Host) -> (Party, Vta) {
    let room = Party::new();
    let owner = vta(
        &room,
        host,
        OWNER_KEY_PATH,
        &["read", "write", "curate", "admin"],
    )
    .await;
    seed_room(host, &room.did, &owner.persona, vti_rooms::Visibility::Open).await;
    (room, owner)
}

/// A batch answers every key in order, each on its own: a record with the host's times, a
/// key the host does not hold as that key's `hostRefused` with the host's code — and none of
/// the single-record members at the top.
#[tokio::test]
async fn read_0_2_answers_each_key_on_its_own_in_order() {
    let s = sealed_room().await;
    owner_writes(&s, "rec-a", "first").await;
    owner_writes(&s, "rec-b", "second").await;

    let got = read_v0_2(
        &s.owner,
        &s.room.did,
        &s.host.did,
        json!({ "keys": ["rec-a", "missing", "rec-b"] }),
    )
    .await;
    let p = &got["payload"];
    assert!(
        got["type"].as_str().unwrap().ends_with("#response"),
        "{got}"
    );
    for absent in ["key", "version", "verification", "plaintext"] {
        assert!(p.get(absent).is_none(), "{absent} at the top: {got}");
    }
    let results = p["results"].as_array().unwrap();
    let keys: Vec<_> = results.iter().map(|r| r["key"].clone()).collect();
    assert_eq!(keys, vec![json!("rec-a"), json!("missing"), json!("rec-b")]);

    assert_eq!(decoded(&results[0]["plaintext"]), "first", "{got}");
    assert_eq!(decoded(&results[2]["plaintext"]), "second", "{got}");
    for r in [&results[0], &results[2]] {
        assert!(r["createdAt"].is_string(), "{r}");
        assert!(r["bodyStoredAt"].is_string(), "{r}");
        assert_eq!(r["verification"]["trace"], "verified", "{r}");
        assert!(r.get("error").is_none(), "{r}");
    }

    let missing = &results[1];
    assert_eq!(
        missing["error"]["code"], "rooms/keys/read:hostRefused",
        "{got}"
    );
    assert_eq!(missing["error"]["retryable"], false, "{got}");
    assert!(missing["error"]["details"]["code"].is_string(), "{got}");
    assert!(missing.get("version").is_none(), "never both: {got}");

    assert_eq!(s.host.received(GET_V3), 3, "each key its own get/0.3");
    assert_eq!(s.host.received(GET_V2), 0);
}

/// A request naming `key` is answered as 0.1 answers it, with the host's times — and 0.1
/// itself, reading with get/0.2, carries none of them.
#[tokio::test]
async fn read_0_2_of_one_key_passes_the_hosts_times_through() {
    let s = sealed_room().await;
    owner_writes(&s, "rec-a", "first").await;

    let got = read_v0_2(
        &s.owner,
        &s.room.did,
        &s.host.did,
        json!({ "key": "rec-a" }),
    )
    .await;
    let p = &got["payload"];
    assert_eq!(p["key"], "rec-a", "{got}");
    assert_eq!(decoded(&p["plaintext"]), "first");
    assert!(p["createdAt"].is_string(), "{got}");
    assert!(p["bodyStoredAt"].is_string(), "{got}");
    assert!(p.get("results").is_none(), "{got}");

    let old = read_record(&s.owner, &s, "rec-a").await;
    assert_eq!(plaintext_of(&old), "first");
    for member in ["createdAt", "createdBy", "bodyStoredAt"] {
        assert!(old["payload"].get(member).is_none(), "{member}: {old}");
    }
}

/// A host that predates `rooms/records/get/0.3` answers it `unsupportedType`: the record is
/// read with get/0.2 and carries none of the host's times — and the rest of the batch asks
/// get/0.2 straight away.
#[tokio::test]
async fn read_0_2_falls_back_to_get_0_2_once_per_request() {
    let s = sealed_room_on(start_host_opts(false, true).await).await;
    owner_writes(&s, "rec-a", "first").await;
    owner_writes(&s, "rec-b", "second").await;

    let got = read_v0_2(
        &s.owner,
        &s.room.did,
        &s.host.did,
        json!({ "keys": ["rec-a", "rec-b"] }),
    )
    .await;
    let results = got["payload"]["results"].as_array().unwrap().clone();
    assert_eq!(decoded(&results[0]["plaintext"]), "first", "{got}");
    assert_eq!(decoded(&results[1]["plaintext"]), "second", "{got}");
    for r in &results {
        for member in ["createdAt", "createdBy", "bodyStoredAt"] {
            assert!(r.get(member).is_none(), "{member}: {r}");
        }
    }
    assert_eq!(s.host.received(GET_V3), 1, "asked once, then remembered");
    assert_eq!(s.host.received(GET_V2), 2);
}

/// A batch stops beginning keys at its size bound: what it read is answered, every key it
/// did not come to is `notAttempted` (retryable, nothing implied), and the host never saw
/// those.
#[tokio::test]
async fn read_0_2_answers_keys_past_its_bound_not_attempted() {
    let s = sealed_room().await;
    owner_writes(&s, "rec-a", "first").await;
    owner_writes(&s, "rec-b", "second").await;

    let got = read_v0_2_within(
        &s.owner,
        &s.room.did,
        &s.host.did,
        json!({ "keys": ["rec-a", "rec-b", "missing"] }),
        super::super::room_read::Budget {
            bytes: 1,
            time: std::time::Duration::from_secs(60),
        },
    )
    .await;
    let results = got["payload"]["results"].as_array().unwrap().clone();
    assert_eq!(decoded(&results[0]["plaintext"]), "first", "{got}");
    for r in &results[1..] {
        assert_eq!(
            r["error"]["code"],
            vti_specs::rooms::keys::read::v0_2::error_codes::NOT_ATTEMPTED.to_string(),
            "{got}"
        );
        assert_eq!(r["error"]["code"], "rooms/keys/read:notAttempted", "{got}");
        assert_eq!(r["error"]["retryable"], true, "{got}");
        assert!(r["error"].get("details").is_none(), "{got}");
    }
    assert_eq!(s.host.received(GET_V3), 1, "only the key it read");
    assert_eq!(
        super::super::room_read::outcomes(&got["payload"]["results"]).len(),
        3
    );
}

/// What concerns the request as a whole is one refusal, before the host is asked anything:
/// both or neither of `key` and `keys`, more than 32, the same key twice.
#[tokio::test]
async fn read_0_2_refuses_a_malformed_batch_whole() {
    let s = sealed_room().await;
    let thirty_three: Vec<String> = (0..33).map(|i| format!("rec-{i}")).collect();
    let thirty_two: Vec<String> = (0..32).map(|i| format!("rec-{i}")).collect();
    for which in [
        json!({ "keys": thirty_three }),
        json!({ "keys": ["rec-a", "rec-a"] }),
        json!({ "keys": [] }),
        json!({ "key": "rec-a", "keys": ["rec-b"] }),
        json!({}),
    ] {
        let got = read_v0_2(&s.owner, &s.room.did, &s.host.did, which.clone()).await;
        assert_eq!(got["payload"]["code"], "malformedRequest", "{which}: {got}");
        assert!(got["payload"].get("results").is_none(), "{got}");
    }
    assert_eq!(s.host.received(GET_V3), 0);

    // Thirty-two is the bound, not past it: every key is read (none is held here).
    let got = read_v0_2(
        &s.owner,
        &s.room.did,
        &s.host.did,
        json!({ "keys": thirty_two }),
    )
    .await;
    let results = got["payload"]["results"].as_array().unwrap();
    assert_eq!(results.len(), super::super::room_read::MAX_KEYS, "{got}");
    assert!(
        results
            .iter()
            .all(|r| r["error"]["code"] == "rooms/keys/read:hostRefused"),
        "{got}"
    );
    assert_eq!(s.host.received(GET_V3), 32);
}

/// **Repairs are per batch.** A member behind by a commit, reading a page of records sealed
/// under the epoch it has not reached and one written before it joined, catches up once and
/// fetches the history once — and every record opens.
#[tokio::test]
async fn a_batch_repairs_once_and_opens_every_record() {
    let s = sealed_room().await;
    owner_writes(&s, "rec-early", "written at epoch 1").await;
    let a = admit(&s, &["read"]).await;
    let _b = admit_at(&s, SECOND_MEMBER_KEY_PATH, &["read"]).await;
    assert_eq!(held(&a, &s).await.epoch, 2);
    let mut keys = vec!["rec-early".to_string()];
    for i in 0..4 {
        owner_writes(&s, &format!("rec-{i}"), &format!("record {i}")).await;
        keys.push(format!("rec-{i}"));
    }
    let commits_before = s.host.received(vti_rooms::wire::ROOMS_EPOCH_COMMITS_TYPE);
    let chain_before = s.host.received(vti_rooms::wire::ROOMS_EPOCH_CHAIN_V2_TYPE);

    let got = read_v0_2(&a, &s.room.did, &s.host.did, json!({ "keys": keys })).await;
    let results = got["payload"]["results"].as_array().unwrap().clone();
    assert_eq!(
        decoded(&results[0]["plaintext"]),
        "written at epoch 1",
        "{got}"
    );
    for i in 0..4 {
        assert_eq!(
            decoded(&results[i + 1]["plaintext"]),
            format!("record {i}"),
            "{got}"
        );
    }
    assert_eq!(
        s.host.received(vti_rooms::wire::ROOMS_EPOCH_COMMITS_TYPE) - commits_before,
        1,
        "one catch-up for the batch"
    );
    assert_eq!(
        s.host.received(vti_rooms::wire::ROOMS_EPOCH_CHAIN_V2_TYPE) - chain_before,
        1,
        "one chain extension for the batch"
    );
    assert_eq!(held(&a, &s).await.epoch, 3);
    assert_eq!(held(&a, &s).await.earliest_readable_epoch, 1);
}

/// One key that will not open is that key's `cannotOpen`, with its reason and epoch, and
/// never fails the record beside it.
#[tokio::test]
async fn a_record_that_will_not_open_fails_only_its_own_key() {
    let s = sealed_room().await;
    let a = admit(&s, &["read"]).await;
    owner_writes(&s, "rec-good", "readable").await;
    vti_rooms::storage::advance_epoch(
        s.host.state.rooms(),
        &s.room.did,
        3,
        Utc::now().timestamp() as u64,
    )
    .await
    .unwrap();
    put_sealed(
        &s,
        "rec-unreachable",
        3,
        "AAAA".into(),
        "AAAAAAAAAAAAAAAA".into(),
    )
    .await;

    let got = read_v0_2(
        &a,
        &s.room.did,
        &s.host.did,
        json!({ "keys": ["rec-unreachable", "rec-good"] }),
    )
    .await;
    let results = got["payload"]["results"].as_array().unwrap().clone();
    let e = &results[0]["error"];
    assert_eq!(e["code"], "rooms/keys/read:cannotOpen", "{got}");
    assert_eq!(e["details"]["reason"], "notDelivered", "{got}");
    assert_eq!(e["details"]["epoch"], 3, "{got}");
    assert_eq!(e["retryable"], false, "{got}");
    assert_eq!(decoded(&results[1]["plaintext"]), "readable", "{got}");

    // The same key alone is refused with exactly that code.
    let alone = read_v0_2(
        &a,
        &s.room.did,
        &s.host.did,
        json!({ "key": "rec-unreachable" }),
    )
    .await;
    assert_eq!(alone["payload"]["code"], *e.get("code").unwrap(), "{alone}");
}

/// The declared refusals of read/0.2 and browse/0.4: no membership is `notAMember`; a host
/// nobody answers at is `hostUnreachable` (per key in a batch); one that does not serve the
/// room is browse's `hostRefused`.
#[tokio::test]
async fn read_0_2_and_browse_0_4_name_their_refusals() {
    let mut s = sealed_room().await;
    let stranger = Party::new().did;
    let got = read_v0_2(&s.owner, &stranger, &s.host.did, json!({ "key": "k" })).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::read::v0_2::error_codes::NOT_A_MEMBER.to_string(),
        "{got}"
    );
    assert_eq!(
        got["payload"]["code"], "rooms/keys/read:notAMember",
        "{got}"
    );
    let got = browse_v0_4(&s.owner, &stranger, &s.host.did).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_4::error_codes::NOT_A_MEMBER.to_string(),
        "{got}"
    );

    let (dead, doc) = unreachable_host();
    knows(&mut s.owner, &dead, doc).await;
    let got = read_v0_2(&s.owner, &s.room.did, &dead, json!({ "key": "k" })).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::read::v0_2::error_codes::HOST_UNREACHABLE.to_string(),
        "{got}"
    );
    let got = read_v0_2(&s.owner, &s.room.did, &dead, json!({ "keys": ["k", "l"] })).await;
    for r in got["payload"]["results"].as_array().unwrap() {
        assert_eq!(
            r["error"]["code"], "rooms/keys/read:hostUnreachable",
            "{got}"
        );
        assert_eq!(r["error"]["retryable"], true, "{got}");
    }
    let got = browse_v0_4(&s.owner, &s.room.did, &dead).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_4::error_codes::HOST_UNREACHABLE.to_string(),
        "{got}"
    );

    let other = start_host().await;
    knows(&mut s.owner, &other.did, other.doc.clone()).await;
    let got = browse_v0_4(&s.owner, &s.room.did, &other.did).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_4::error_codes::HOST_REFUSED.to_string(),
        "{got}"
    );
    let got = read_v0_2(&s.owner, &s.room.did, &other.did, json!({ "key": "k" })).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::read::v0_2::error_codes::HOST_REFUSED.to_string(),
        "{got}"
    );
}

/// browse/0.4 passes list/0.6's rows through as served — `createdAt`, `createdBy`,
/// `bodyStoredAt`, and on an open room `kind` — and a host that predates list/0.6 is listed
/// with 0.5, its rows carrying none of them.
#[tokio::test]
async fn browse_0_4_passes_list_0_6_rows_through_and_falls_back_to_0_5() {
    for predates in [false, true] {
        let host = start_host_opts(false, predates).await;
        let (room, owner) = open_room_on(&host).await;
        put_open_v0_5(
            &owner,
            &room.did,
            &host,
            "msg-1",
            json!({ "body": "hello", "kind": "message" }),
        )
        .await;

        let got = browse_v0_4(&owner, &room.did, &host.did).await;
        let p = &got["payload"];
        assert!(
            got["type"].as_str().unwrap().ends_with("#response"),
            "{got}"
        );
        assert_eq!(p["complete"], true, "{got}");
        assert_eq!(p["verification"]["count"], "agrees", "{got}");
        let row = &p["records"][0];
        assert_eq!(row["key"], "msg-1", "{got}");
        if predates {
            for member in ["createdAt", "createdBy", "bodyStoredAt", "kind"] {
                assert!(row.get(member).is_none(), "{member}: {got}");
            }
            assert_eq!(host.received(LIST_V6), 1, "asked once");
            assert_eq!(host.received(LIST_V5), 1);
        } else {
            assert_eq!(row["kind"], "message", "{got}");
            assert_eq!(row["createdBy"], owner.persona, "{got}");
            assert!(row["createdAt"].is_string(), "{got}");
            assert!(row["bodyStoredAt"].is_string(), "{got}");
            assert_eq!(host.received(LIST_V5), 0);
        }
        // browse/0.3 is unchanged: list/0.5, its rows without the new members.
        let old = body(
            super::super::room_group::handle_browse_v0_3(
                &owner.state,
                &admin(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_3,
                    json!({ "roomId": room.did, "host": host.did }),
                ),
            )
            .await,
        );
        assert!(
            old["payload"]["records"][0].get("createdAt").is_none(),
            "{old}"
        );
    }
}

// ─── `rooms/keys/browse/0.5` (trust-tasks-tf #1088) ─────────────────────────────────────
//
// `order` passed through to the host's list/0.7, `maxPages` stopping the read, the host's
// cursor answered as `nextCursor` and taken back as `cursor`, and `hostRefused` — never an
// oldest-first listing — for `newestFirst` at a host that predates list/0.7.

const BROWSE_0_5: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_5;
const LIST_V7: &str = vti_rooms::wire::ROOMS_RECORDS_LIST_V7_TYPE;

async fn browse_v0_5(v: &Vta, room: &str, host: &str, extra: Value) -> Value {
    let mut payload = json!({ "roomId": room, "host": host });
    for (k, val) in extra.as_object().unwrap() {
        payload[k] = val.clone();
    }
    body(
        super::super::room_group::handle_browse_v0_5(
            &v.state,
            &admin(),
            request(BROWSE_0_5, payload),
        )
        .await,
    )
}

fn row_versions(got: &Value) -> Vec<u64> {
    got["payload"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["version"].as_u64().unwrap())
        .collect()
}

/// An open room on `host` holding the messages `m0`…`m{n-1}`, written in that order.
async fn open_room_with(host: &Host, n: usize) -> (Party, Vta) {
    let (room, owner) = open_room_on(host).await;
    for i in 0..n {
        put_open_v0_5(
            &owner,
            &room.did,
            host,
            &format!("m{i}"),
            json!({ "body": format!("message {i}") }),
        )
        .await;
    }
    (room, owner)
}

/// *Order and paging* items 1–6: a newest-first browse with `maxPages: 1` returns the head
/// page in descending `version`, `complete: false` with the host's cursor as `nextCursor`
/// and a count that is not comparable; passing that cursor back continues downward, and a
/// browse resumed from a cursor is never compared against `recordCount`, even at the end.
#[tokio::test]
async fn browse_0_5_opens_a_conversation_at_its_head_and_pages_back() {
    let host = start_host().await;
    let (room, owner) = open_room_with(&host, 5).await;

    let head = browse_v0_5(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst", "limit": 2, "maxPages": 1 }),
    )
    .await;
    let p = &head["payload"];
    assert!(
        head["type"].as_str().unwrap().ends_with("#response"),
        "{head}"
    );
    let first = row_versions(&head);
    assert_eq!(first.len(), 2, "{head}");
    assert!(first[0] > first[1], "descending: {head}");
    assert_eq!(p["complete"], false, "{head}");
    assert_eq!(p["verification"]["count"], "notComparable", "{head}");
    let cursor = p["nextCursor"]
        .as_str()
        .expect("the host's cursor")
        .to_string();
    assert_eq!(host.received(LIST_V7), 1, "one host page");

    // Back, a page at a time, to the end.
    let mut seen = first.clone();
    let mut cursor = Some(cursor);
    let mut last = Value::Null;
    while let Some(c) = cursor {
        last = browse_v0_5(
            &owner,
            &room.did,
            &host.did,
            json!({ "order": "newestFirst", "limit": 2, "maxPages": 1, "cursor": c }),
        )
        .await;
        seen.extend(row_versions(&last));
        cursor = last["payload"]["nextCursor"].as_str().map(str::to_string);
        assert_eq!(
            last["payload"]["complete"],
            cursor.is_none(),
            "`complete` and `nextCursor` agree: {last}"
        );
    }
    assert!(seen.windows(2).all(|w| w[0] > w[1]), "downward: {seen:?}");
    assert_eq!(
        last["payload"]["verification"]["count"], "notComparable",
        "a resumed listing is never compared: {last}"
    );

    // The whole room newest first, in one browse, is comparable — the order is no filter.
    let whole = browse_v0_5(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst" }),
    )
    .await;
    assert_eq!(whole["payload"]["complete"], true, "{whole}");
    assert!(whole["payload"].get("nextCursor").is_none(), "{whole}");
    assert_eq!(
        whole["payload"]["verification"]["count"], "agrees",
        "{whole}"
    );
    assert_eq!(
        row_versions(&whole),
        seen,
        "the same records, the same order"
    );
}

/// Item 3: the agent stops at `maxPages` however many pages remain; without it, a browse
/// reads to the end as before (and oldest first, as 0.4 does).
#[tokio::test]
async fn browse_0_5_stops_at_max_pages() {
    let host = start_host().await;
    let (room, owner) = open_room_with(&host, 5).await;
    let got = browse_v0_5(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst", "limit": 1, "maxPages": 2 }),
    )
    .await;
    assert_eq!(row_versions(&got).len(), 2, "{got}");
    assert_eq!(host.received(LIST_V7), 2);
    assert_eq!(got["payload"]["complete"], false, "{got}");

    let all = browse_v0_5(&owner, &room.did, &host.did, json!({ "limit": 1 })).await;
    let up = row_versions(&all);
    assert!(
        up.windows(2).all(|w| w[0] < w[1]),
        "oldest first by default: {up:?}"
    );
    assert_eq!(all["payload"]["complete"], true, "{all}");
    assert!(all["payload"].get("nextCursor").is_none(), "{all}");
}

/// Item 1: at a host that predates list/0.7, a `newestFirst` browse is `hostRefused` with
/// the host's refusal in `details` — never listed oldest first — while a browse that asks
/// no order, or `oldestFirst`, is listed with list/0.6. And item 5: a cursor the host did
/// not issue for this order is the host's to refuse, answered `hostRefused`.
#[tokio::test]
async fn browse_0_5_refuses_newest_first_at_a_host_without_list_0_7() {
    const PREDATES_V7: &[&str] = &[vti_rooms::wire::ROOMS_RECORDS_LIST_V7_TYPE];
    let host = start_host_refusing(false, PREDATES_V7).await;
    let (room, owner) = open_room_with(&host, 2).await;

    let got = browse_v0_5(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst" }),
    )
    .await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_5::error_codes::HOST_REFUSED.to_string(),
        "{got}"
    );
    assert_eq!(
        got["payload"]["details"]["code"], "unsupportedType",
        "{got}"
    );
    assert_eq!(host.received(LIST_V6), 0, "never listed oldest first");

    for order in [json!({}), json!({ "order": "oldestFirst" })] {
        let got = browse_v0_5(&owner, &room.did, &host.did, order).await;
        assert_eq!(got["payload"]["complete"], true, "{got}");
        let up = row_versions(&got);
        assert!(up.windows(2).all(|w| w[0] < w[1]), "{up:?}");
    }
    assert_eq!(host.received(LIST_V6), 2);

    // At a host serving list/0.7, an oldest-first cursor offered under `newestFirst`.
    let host = start_host().await;
    let (room, owner) = open_room_with(&host, 3).await;
    let up = browse_v0_5(
        &owner,
        &room.did,
        &host.did,
        json!({ "limit": 1, "maxPages": 1 }),
    )
    .await;
    let cursor = up["payload"]["nextCursor"].as_str().expect("more remain");
    let got = browse_v0_5(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst", "cursor": cursor }),
    )
    .await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_5::error_codes::HOST_REFUSED.to_string(),
        "{got}"
    );
    assert_eq!(
        got["payload"]["details"]["code"],
        vti_specs::rooms::records::list::v0_7::error_codes::INVALID_CURSOR.to_string(),
        "{got}"
    );
}

// ─── `rooms/keys/browse/0.6` (trust-tasks-tf #1289) ─────────────────────────────────────
//
// `beforeVersion` passed through to the host's list/0.8, and `hostRefused` — never a listing
// without the bound — at a host that predates list/0.8.

const BROWSE_0_6: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_6;
const LIST_V8: &str = vti_rooms::wire::ROOMS_RECORDS_LIST_V8_TYPE;

async fn browse_v0_6(v: &Vta, room: &str, host: &str, extra: Value) -> Value {
    let mut payload = json!({ "roomId": room, "host": host });
    for (k, val) in extra.as_object().unwrap() {
        payload[k] = val.clone();
    }
    body(
        super::super::room_group::handle_browse_v0_6(
            &v.state,
            &admin(),
            request(BROWSE_0_6, payload),
        )
        .await,
    )
}

/// "Load older" from the lowest version a surface holds, with no cursor kept: the rows
/// below it, newest first, never comparable against `recordCount` — even read to the end.
#[tokio::test]
async fn browse_0_6_loads_older_from_a_version() {
    let host = start_host().await;
    let (room, owner) = open_room_with(&host, 5).await;
    let head = browse_v0_6(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst", "limit": 2, "maxPages": 1 }),
    )
    .await;
    let top = row_versions(&head);
    assert_eq!(top.len(), 2, "{head}");
    assert_eq!(host.received(LIST_V8), 1, "list/0.8 at the host");
    let lowest = *top.iter().min().unwrap();

    let older = browse_v0_6(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst", "beforeVersion": lowest }),
    )
    .await;
    let below = row_versions(&older);
    assert!(!below.is_empty(), "{older}");
    assert!(below.iter().all(|v| *v < lowest), "{older}");
    assert!(below.windows(2).all(|w| w[0] > w[1]), "downward: {below:?}");
    assert_eq!(older["payload"]["complete"], true, "{older}");
    assert_eq!(
        older["payload"]["verification"]["count"], "notComparable",
        "a listing bounded above is never compared: {older}"
    );
}

/// At a host without list/0.8, a browse naming `beforeVersion` is `hostRefused` with the
/// host's refusal — never listed without the bound; one that names none is listed with
/// list/0.7, newest first as asked.
#[tokio::test]
async fn browse_0_6_refuses_before_version_at_a_host_without_list_0_8() {
    const PREDATES_V8: &[&str] = &[vti_rooms::wire::ROOMS_RECORDS_LIST_V8_TYPE];
    let host = start_host_refusing(false, PREDATES_V8).await;
    let (room, owner) = open_room_with(&host, 3).await;

    let got = browse_v0_6(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst", "beforeVersion": 3 }),
    )
    .await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_6::error_codes::HOST_REFUSED.to_string(),
        "{got}"
    );
    assert_eq!(
        got["payload"]["details"]["code"], "unsupportedType",
        "{got}"
    );
    assert_eq!(host.received(LIST_V7), 0, "never listed without the bound");

    let got = browse_v0_6(
        &owner,
        &room.did,
        &host.did,
        json!({ "order": "newestFirst" }),
    )
    .await;
    assert_eq!(got["payload"]["complete"], true, "{got}");
    let down = row_versions(&got);
    assert!(down.windows(2).all(|w| w[0] > w[1]), "{down:?}");
    assert_eq!(host.received(LIST_V7), 1);
}

/// browse/0.6 names its refusals at its own version: no membership is `notAMember`; a host
/// nobody answers at is `hostUnreachable`.
#[tokio::test]
async fn browse_0_6_names_its_refusals() {
    let mut s = sealed_room().await;
    let stranger = Party::new().did;
    let got = browse_v0_6(&s.owner, &stranger, &s.host.did, json!({})).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_6::error_codes::NOT_A_MEMBER.to_string(),
        "{got}"
    );

    let (dead, doc) = unreachable_host();
    knows(&mut s.owner, &dead, doc).await;
    let got = browse_v0_6(&s.owner, &s.room.did, &dead, json!({ "beforeVersion": 9 })).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_6::error_codes::HOST_UNREACHABLE.to_string(),
        "{got}"
    );
}

/// browse/0.5 names its refusals as 0.4 does, at its own version: no membership is
/// `notAMember`; a host nobody answers at is `hostUnreachable`.
#[tokio::test]
async fn browse_0_5_names_its_refusals() {
    let mut s = sealed_room().await;
    let stranger = Party::new().did;
    let got = browse_v0_5(&s.owner, &stranger, &s.host.did, json!({})).await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_5::error_codes::NOT_A_MEMBER.to_string(),
        "{got}"
    );
    assert_eq!(
        got["payload"]["code"], "rooms/keys/browse:notAMember",
        "{got}"
    );

    let (dead, doc) = unreachable_host();
    knows(&mut s.owner, &dead, doc).await;
    let got = browse_v0_5(
        &s.owner,
        &s.room.did,
        &dead,
        json!({ "order": "newestFirst" }),
    )
    .await;
    assert_eq!(
        got["payload"]["code"],
        vti_specs::rooms::keys::browse::v0_5::error_codes::HOST_UNREACHABLE.to_string(),
        "{got}"
    );
}

/// **End to end, on an open room whose profile lists the members.** The writer reads the
/// profile and is permitted `kind`, `inReplyTo` and `writtenAt` (and not `editedAt`); writes
/// a message, a reply to it and a reaction with `rooms/records/put/0.5` through
/// `rooms/keys/act/0.11`; and a member reads all three back in one `rooms/keys/read/0.2`
/// batch — each record's `kind` and `inReplyTo` as written, and the host's times.
#[tokio::test]
async fn messages_replies_and_reactions_round_trip_through_a_batch_read() {
    let host = start_host().await;
    let (room, owner) = open_room_on(&host).await;
    let mut profile = board();
    profile["recordMembers"] = json!(["kind", "inReplyTo", "writtenAt"]);
    let w = write_profile(&owner, &room.did, &host, profile).await;
    assert_eq!(w["payload"]["outcome"], "written", "{w}");

    // The writer's rule, against the profile as its readers see it.
    let read = read(&owner, &room.did, &host).await;
    let listed: Vec<String> =
        serde_json::from_value(read["payload"]["profile"]["recordMembers"].clone())
            .unwrap_or_else(|e| panic!("{e}: {read}"));
    let written_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let message = json!({ "body": "Shall we meet on Thursday?", "kind": "message",
                          "writtenAt": written_at });
    let reply = json!({ "body": "Thursday works.", "kind": "message",
                        "inReplyTo": { "key": "msg-1" }, "writtenAt": written_at });
    for body in [&message, &reply] {
        vti_rooms::record_members::permitted(body.as_object().unwrap(), Some(&listed))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let edited = json!({ "body": "x", "editedAt": written_at });
    assert!(
        vti_rooms::record_members::permitted(edited.as_object().unwrap(), Some(&listed)).is_err(),
        "`editedAt` is not listed"
    );

    let first = put_open_v0_5(&owner, &room.did, &host, "msg-1", message).await;
    let version = first["version"].as_u64().unwrap();
    put_open_v0_5(&owner, &room.did, &host, "reply-1", reply).await;
    let reaction = json!({ "body": "👍", "kind": "reaction",
                           "inReplyTo": { "key": "msg-1", "version": version } });
    vti_rooms::record_members::permitted(reaction.as_object().unwrap(), Some(&listed)).unwrap();
    put_open_v0_5(&owner, &room.did, &host, "react-1", reaction).await;

    let got = read_v0_2(
        &owner,
        &room.did,
        &host.did,
        json!({ "keys": ["msg-1", "reply-1", "react-1"] }),
    )
    .await;
    let results = got["payload"]["results"].as_array().unwrap().clone();
    assert_eq!(results.len(), 3, "{got}");
    for r in &results {
        assert!(r.get("error").is_none(), "{got}");
        assert_eq!(r["createdBy"], owner.persona, "{got}");
        assert!(r["createdAt"].is_string(), "{got}");
        assert!(r["bodyStoredAt"].is_string(), "{got}");
        assert!(
            r.get("plaintext").is_none(),
            "an open room's body is cleartext"
        );
    }
    assert_eq!(results[0]["cleartext"]["kind"], "message", "{got}");
    assert_eq!(results[0]["cleartext"]["writtenAt"], written_at, "{got}");
    assert!(results[0]["cleartext"].get("inReplyTo").is_none(), "{got}");
    assert_eq!(results[1]["cleartext"]["kind"], "message", "{got}");
    assert_eq!(
        results[1]["cleartext"]["inReplyTo"],
        json!({ "key": "msg-1" }),
        "{got}"
    );
    assert_eq!(results[2]["cleartext"]["kind"], "reaction", "{got}");
    assert_eq!(
        results[2]["cleartext"]["inReplyTo"],
        json!({ "key": "msg-1", "version": version }),
        "{got}"
    );
    assert_eq!(results[2]["cleartext"]["body"], "👍", "{got}");
}

/// `rooms/keys/watch`, `rooms/keys/changed` and `rooms/keys/act/0.12`, on these fixtures.
/// The pass-on rides the push path, which a build without DIDComm has no route for.
#[cfg(feature = "didcomm")]
#[path = "room_key_watch_tests.rs"]
mod watch;

// ─── Purpose of use (VTI-ACL-100 – 110) ─────────────────────────────────────

/// The super admin's stored entry, narrowed to `purposes`.
async fn narrow(state: &AppState, purposes: &[&str]) {
    let did = admin().did;
    let mut entry = crate::acl::get_acl_entry(&state.acl_ks, &did)
        .await
        .unwrap()
        .expect("the super admin's entry");
    entry.purposes = vti_common::acl::PurposeScope::listed(purposes.iter().copied()).unwrap();
    crate::acl::store_acl_entry(&state.acl_ks, &entry)
        .await
        .unwrap();
}

/// The audit rows the VTA wrote, as text.
async fn audit_rows(state: &AppState) -> Vec<String> {
    state
        .audit_ks
        .prefix_iter_raw("log:")
        .await
        .unwrap()
        .into_iter()
        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
        .collect()
}

/// `rooms/keys/read/0.3` (VTI-ACL-102 – 106): a read is held to the caller's purposes
/// before the host is asked for anything, refused distinctly and without content, and
/// audited with its purpose either way. A granted purpose is passed to the host as
/// get/0.4's, which the host serves.
#[tokio::test]
async fn read_0_3_is_held_to_the_callers_purposes() {
    let s = sealed_room().await;
    owner_writes(&s, "rec-a", "first").await;
    narrow(&s.owner.state, &["personalisation", "taskExecution"]).await;
    let caller = admin();
    let read3 = |purpose: Option<&str>| {
        let mut payload = json!({ "roomId": s.room.did, "host": s.host.did, "key": "rec-a" });
        if let Some(p) = purpose {
            payload["purpose"] = json!(p);
        }
        super::super::room_read::handle_read_v0_3(
            &s.owner.state,
            &caller,
            request(vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_3, payload),
        )
    };
    let (v3_before, v4) = (
        s.host.received(GET_V3),
        vti_rooms::wire::ROOMS_RECORDS_GET_V4_TYPE,
    );

    let refused = body(read3(Some("analytics")).await);
    assert_eq!(
        refused["payload"]["code"], "rooms/keys/read:purposeNotGranted",
        "{refused}"
    );
    assert_eq!(
        refused["payload"]["details"],
        json!({ "purposeNamed": true, "purpose": "analytics" })
    );
    assert!(
        !refused.to_string().contains("first"),
        "no content: {refused}"
    );
    let unnamed = body(read3(None).await);
    assert_eq!(
        unnamed["payload"]["details"],
        json!({ "purposeNamed": false }),
        "two purposes listed and none named: {unnamed}"
    );
    assert_eq!(
        s.host.received(GET_V3),
        v3_before,
        "a refused read asks the host for nothing"
    );

    let served = body(read3(Some("personalisation")).await);
    assert_eq!(
        decoded(&served["payload"]["plaintext"]),
        "first",
        "{served}"
    );
    assert_eq!(s.host.received(v4), 1, "the purpose is offered to the host");
    assert_eq!(
        s.host.received(GET_V3),
        v3_before,
        "a host serving get/0.4 is not asked get/0.3"
    );

    let rows = audit_rows(&s.owner.state).await;
    assert!(
        rows.iter()
            .any(|r| r.contains("rooms.keys.read") && r.contains("purpose=personalisation")),
        "{rows:#?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("rooms.keys.read")
            && r.contains("refused=purposeNotGranted purpose=analytics")),
        "{rows:#?}"
    );
}

/// `rooms/keys/read/0.3` against a host that does not serve get/0.4: the read, its
/// purpose already decided here, is asked as get/0.3.
#[tokio::test]
async fn read_0_3_falls_back_to_get_0_3_on_a_host_without_get_0_4() {
    let s = sealed_room_on(
        start_host_refusing(false, &[vti_rooms::wire::ROOMS_RECORDS_GET_V4_TYPE]).await,
    )
    .await;
    owner_writes(&s, "rec-a", "first").await;
    narrow(&s.owner.state, &["personalisation"]).await;
    let v3_before = s.host.received(GET_V3);
    let served = body(
        super::super::room_read::handle_read_v0_3(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_3,
                json!({ "roomId": s.room.did, "host": s.host.did, "key": "rec-a",
                        "purpose": "personalisation" }),
            ),
        )
        .await,
    );
    assert_eq!(
        decoded(&served["payload"]["plaintext"]),
        "first",
        "{served}"
    );
    assert_eq!(
        s.host.received(vti_rooms::wire::ROOMS_RECORDS_GET_V4_TYPE),
        1
    );
    assert_eq!(
        s.host.received(GET_V3),
        v3_before + 1,
        "asked get/0.3 after"
    );
}

/// `rooms/owner/issue-authority/0.3` (VTI-ACL-110): the credential states the request's
/// `purposes` unchanged, and a grant wider than the caller's own entry — a purpose it does
/// not hold, or none at all, which grants `any` — is refused, never issued narrower
/// (VTI-ACL-107).
#[tokio::test]
async fn issue_authority_0_3_states_the_purposes_asked_within_the_callers() {
    let s = sealed_room().await;
    let room_signing =
        crate::test_support::seed_holder_key(&s.owner.state, ROOM_KEY_PATH, None).await;
    let room_key = format!(
        "{room_signing}#{}",
        room_signing.strip_prefix("did:key:").unwrap()
    );
    let grant = |uri: &'static str, purposes: Option<Value>| {
        let mut payload = json!({
            "roomId": s.room.did, "signingKeyId": room_key,
            "subject": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "actions": ["read"],
            "validUntil": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        });
        if let Some(p) = purposes {
            payload["purposes"] = p;
        }
        let state = &s.owner.state;
        async move {
            let doc = request(uri, payload);
            body(
                if uri == vta_sdk::trust_tasks::TASK_ROOMS_OWNER_ISSUE_AUTHORITY_0_3 {
                    super::super::room_owner::handle_issue_authority_v0_3(state, &admin(), doc)
                        .await
                } else {
                    super::super::room_owner::handle_issue_authority(state, &admin(), doc).await
                },
            )
        }
    };
    const V3: &str = vta_sdk::trust_tasks::TASK_ROOMS_OWNER_ISSUE_AUTHORITY_0_3;
    const V2: &str = vta_sdk::trust_tasks::TASK_ROOMS_OWNER_ISSUE_AUTHORITY_0_2;
    let one = json!({ "scope": "listed", "purposes": ["taskExecution"] });

    // A caller under `any` may grant a list, and the credential states it unchanged.
    let issued = grant(V3, Some(one.clone())).await;
    let vac: dtg_credentials::DTGCredential =
        serde_json::from_str(issued["payload"]["credential"].as_str().expect("{issued}"))
            .expect("the credential reads");
    let vac = serde_json::to_value(&vac).unwrap();
    assert_eq!(vac["credentialSubject"]["purposes"], one, "{vac}");
    assert_eq!(vac["@context"][1], dtg_credentials::DTG_CONTEXT_V2, "{vac}");
    // And under `any`, a request stating none issues a credential stating none.
    let none = grant(V2, None).await;
    let vac: Value =
        serde_json::from_str(none["payload"]["credential"].as_str().expect("{none}")).unwrap();
    assert!(vac["credentialSubject"].get("purposes").is_none(), "{vac}");

    narrow(&s.owner.state, &["taskExecution", "personalisation"]).await;
    assert!(grant(V3, Some(one)).await["payload"]["credential"].is_string());
    for (uri, purposes, why) in [
        (
            V3,
            Some(json!({ "scope": "listed", "purposes": ["analytics"] })),
            "a purpose the caller does not hold",
        ),
        (V3, None, "none stated grants `any`"),
        (V2, None, "0.2 states none"),
    ] {
        let refused = grant(uri, purposes).await;
        assert!(
            refused["payload"].get("credential").is_none(),
            "{why}: {refused}"
        );
    }
}
