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
    _dir: tempfile::TempDir,
}

async fn start_host() -> Host {
    start_host_with(false).await
}

/// [`start_host`]; with `contend`, every `rooms/records/put` loses its predicted version to
/// another write that lands just before it — the version race `rooms/keys/profile/write`
/// item 6 answers `contended` for when it never stops.
async fn start_host_with(contend: bool) -> Host {
    let party = Party::new();
    let dir = tempfile::tempdir().unwrap();
    let state = room_host::open_state(dir.path()).expect("a host");
    state.set_host_did(&party.did).expect("bind the host DID");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = state.clone();
    let host_did = party.did.clone();
    let secret = party.secret_multibase.clone();
    let app = axum::Router::new().route(
        "/trust-tasks",
        axum::routing::post(move |body: axum::body::Bytes| {
            let shared = shared.clone();
            let host_did = host_did.clone();
            let secret = secret.clone();
            async move {
                if contend {
                    let doc: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    if doc["type"] == vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE
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
            epoch_floor: None,
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
/// `rooms/owner/group/add/0.2` at the real host; the member joins from the Welcome.
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
        super::super::room_owner_group::handle_add_v0_2(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_2,
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
            .decode(out["payload"]["welcome"].as_str().expect("{out}"))
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
            vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_RENEW_0_1,
            json!({ "roomId": s.room.did, "host": s.host.did }),
        );
        let state = s.owner.state.clone();
        async move { body(super::super::room_owner_group::handle_renew(&state, &admin(), doc).await) }
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
        super::super::room_group::handle_browse(
            &s.owner.state,
            &admin(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_1,
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
                super::super::room_group::handle_backfill(
                    &s.owner.state,
                    &admin(),
                    request(
                        vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BACKFILL_0_1,
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
