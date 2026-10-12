//! Storage configs and room assignment (`docs/05-design-notes/data-rooms-files.md` §7):
//! `vtc/storage/configs/{list,get,create,update,retire,probe}/0.1` and
//! `vtc/rooms/storage/assign/0.1`, driven through the signed-document door as an
//! administrator's client does — the requester's gesture, then the other holders'
//! approvals for every change.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, AdminRole, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::admin_actions::ActionRecord;
use vtc_service::rooms::storage_configs::codes::*;
use vtc_service::rooms::storage_configs::{SEED_CONFIG_ID, state_of};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::Gesturer;
use crate::common::signed::{error_code, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST: &str = "https://trusttasks.org/spec/vtc/storage/configs/list/0.1";
const GET: &str = "https://trusttasks.org/spec/vtc/storage/configs/get/0.1";
const CREATE: &str = "https://trusttasks.org/spec/vtc/storage/configs/create/0.1";
const UPDATE: &str = "https://trusttasks.org/spec/vtc/storage/configs/update/0.1";
const RETIRE: &str = "https://trusttasks.org/spec/vtc/storage/configs/retire/0.1";
const PROBE: &str = "https://trusttasks.org/spec/vtc/storage/configs/probe/0.1";
const ASSIGN: &str = "https://trusttasks.org/spec/vtc/rooms/storage/assign/0.1";

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

async fn seed(fix: &Fixture, admin: AdminAuthority) -> Party {
    let p = Party::new();
    let row = VtcAclEntry {
        did: p.did.clone(),
        role: VtcRole::implied_by(admin.admin_role.as_ref()),
        label: None,
        admin,
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
    store_acl_entry(&fix.vtc.state.acl_ks, &row).await.unwrap();
    p
}

/// A community administrator holding a passkey, so able to make the gesture.
async fn requester(fix: &mut Fixture) -> Party {
    let p = seed(fix, AdminAuthority::community_admin()).await;
    fix.gesturer.enrol(&fix.vtc, &p.did).await;
    p
}

async fn send(fix: &Fixture, by: &Party, uri: &str, payload: Value) -> Value {
    post(&fix.vtc, &signed(by, uri, payload).await).await.1
}

async fn through(
    fix: &mut Fixture,
    by: &Party,
    approvers: &[&Party],
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let doc = signed(by, uri, payload).await;
    fix.gesturer
        .send_through(&fix.vtc, by, approvers, &doc)
        .await
}

fn root(fix: &Fixture, name: &str) -> String {
    fix.vtc
        .data_dir()
        .join("room-storage")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn local(root: &str) -> Value {
    json!({ "kind": "local", "root": root })
}

/// A config stored directly, as an executed create would leave it.
async fn stored(fix: &Fixture, id: &str, state: &str) {
    let r = root(fix, id);
    std::fs::create_dir_all(&r).unwrap();
    let record = json!({
        "id": id,
        "label": id,
        "settings": local(&r),
        "state": state,
        "createdBy": "did:key:zAdmin",
        "createdAt": chrono::Utc::now().to_rfc3339(),
    });
    let _guard = fix.vtc.state.room_storage.lock().await;
    fix.vtc.state.room_storage.put_config(record).await.unwrap();
}

/// A hosted room, assigned to the default config as creation assigns it.
async fn hosted_room(fix: &Fixture) -> String {
    let room_id = format!("did:key:z6MkRoom{}", uuid::Uuid::new_v4().simple());
    let room = vti_rooms::Room {
        room_id: room_id.clone(),
        owner_did: "did:key:zOwner".into(),
        visibility: vti_rooms::Visibility::Open,
        retention_policy: vti_rooms::RetentionPolicy::Chained,
        anchor_cadence: Default::default(),
        epoch: 1,
        next_version: 1,
        retention_days: 30,
        epoch_expires_at: None,
        created_at: 0,
        updated_at: 0,
        mirror_of: None,
    };
    vti_rooms::storage::create_room(&fix.vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    fix.vtc
        .state
        .room_storage
        .assign_new_room(&room_id)
        .await
        .unwrap();
    room_id
}

/// A blob recorded under `config_id`, as a committed upload leaves one.
async fn blob_on(fix: &Fixture, config_id: &str) {
    let entry = json!({
        "roomId": "did:key:zSomeRoom",
        "blobRef": "zQmBlob",
        "size": 10,
        "manifest": {},
        "configId": config_id,
        "backendRef": { "kind": "local", "key": "rooms/x/zQmBlob" },
        "state": "committed",
        "refs": 1,
        "committedAt": 0,
    });
    fix.vtc
        .state
        .room_files
        .index_keyspace()
        .insert(format!("blob:test:{config_id}"), &entry)
        .await
        .unwrap();
}

async fn actions_of_kind(fix: &Fixture, kind: &str) -> Vec<ActionRecord> {
    fix.vtc
        .state
        .admin_actions_ks
        .prefix_iter_raw(b"action:".to_vec())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<ActionRecord>(&v).ok())
        .filter(|r| r.kind == kind)
        .collect()
}

async fn audit_rows(fix: &Fixture) -> Vec<vti_common::audit::AuditEnvelope> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter(|env| env.event.variant_name() == "RoomStorageChanged")
        .collect()
}

// ─── the flows ───────────────────────────────────────────────────────────

/// First start seeds `local` at `[rooms.files] blob_dir` as the default, and a room is
/// assigned to it at creation.
#[tokio::test]
async fn the_seeded_local_config_is_the_default_every_room_starts_on() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let listed = send(&fix, &a, LIST, json!({})).await;
    let items = listed["payload"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{listed}");
    assert_eq!(items[0]["config"]["id"], SEED_CONFIG_ID);
    assert_eq!(items[0]["config"]["isDefault"], true);
    assert_eq!(items[0]["facts"]["credential"]["status"], "none");

    let room = hosted_room(&fix).await;
    let got = send(&fix, &a, GET, json!({ "configId": SEED_CONFIG_ID })).await;
    assert_eq!(got["payload"]["facts"]["rooms"], 1, "{got}");
    assert_eq!(got["payload"]["assignedRooms"], json!([room]));
}

/// A create is parked for another holder of `vtc.rooms.admin`, stores nothing before it
/// is approved, and lands — probed, audited — on the approval.
#[tokio::test]
async fn a_config_is_created_only_on_another_administrators_approval() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = seed(&fix, AdminAuthority::community_admin()).await;
    let r = root(&fix, "eu");

    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        CREATE,
        json!({
            "id": "eu",
            "label": "EU disk",
            "settings": local(&r),
            "capacityBytes": 1_000_000,
            "reason": "a second disk for the EU rooms",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["config"]["id"], "eu");
    assert_eq!(reply["payload"]["config"]["createdBy"], a.did);
    assert_eq!(
        actions_of_kind(&fix, "storage.config.create").await.len(),
        1
    );

    let stored = fix
        .vtc
        .state
        .room_storage
        .config("eu")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state_of(&stored), "active");
    // Created owner-only on execution, and probed once it existed.
    assert!(std::path::Path::new(&r).is_dir());
    let health = fix.vtc.state.room_storage.health("eu").await.unwrap();
    assert_eq!(health["lastProbeOk"], true, "{health}");
    let rows = audit_rows(&fix).await;
    assert_eq!(rows.len(), 1);
}

/// Reassigning a room points its new uploads at the new config, through the action
/// list; reassigning it to where it is changes nothing and parks nothing.
#[tokio::test]
async fn a_room_is_reassigned_through_the_action_list() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = seed(&fix, AdminAuthority::community_admin()).await;
    stored(&fix, "eu", "active").await;
    let room = hosted_room(&fix).await;

    let same = send(
        &fix,
        &a,
        ASSIGN,
        json!({ "roomId": room, "configId": SEED_CONFIG_ID, "reason": "no change" }),
    )
    .await;
    assert_eq!(
        same["payload"]["previousConfigId"], SEED_CONFIG_ID,
        "{same}"
    );
    assert!(
        actions_of_kind(&fix, "rooms.storage.assign")
            .await
            .is_empty()
    );

    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        ASSIGN,
        json!({ "roomId": room, "configId": "eu", "reason": "move to the EU disk" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["previousConfigId"], SEED_CONFIG_ID);
    assert_eq!(reply["payload"]["configId"], "eu");
    let assigned = fix
        .vtc
        .state
        .room_storage
        .assignment(&room)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(assigned.config_id, "eu");
    assert_eq!(assigned.assigned_by, a.did);
    let row = &audit_rows(&fix).await[0];
    let data = serde_json::to_value(&row.event).unwrap();
    assert_eq!(data["data"]["approvers"], json!([b.did]), "{data}");
}

/// A config holding blobs drains; one holding none retires at once. Retiring again
/// changes nothing.
#[tokio::test]
async fn retiring_a_config_drains_it_while_blobs_remain() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = seed(&fix, AdminAuthority::community_admin()).await;
    stored(&fix, "eu", "active").await;
    stored(&fix, "us", "active").await;
    blob_on(&fix, "eu").await;

    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        RETIRE,
        json!({ "configId": "eu", "reason": "closing the EU disk" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["state"], "draining");
    assert_eq!(reply["payload"]["blobsRemaining"], 1);

    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        RETIRE,
        json!({ "configId": "us", "reason": "never used" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["state"], "retired");

    let again = send(
        &fix,
        &a,
        RETIRE,
        json!({ "configId": "us", "reason": "again" }),
    )
    .await;
    assert_eq!(again["payload"]["state"], "retired", "{again}");
}

/// The probe writes, reads back and deletes a canary under `probe/`, never under a
/// room's prefix, and records the result.
#[tokio::test]
async fn the_probe_round_trips_a_canary_outside_every_room() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let reply = send(&fix, &a, PROBE, json!({ "configId": SEED_CONFIG_ID })).await;
    assert_eq!(reply["payload"]["ok"], true, "{reply}");
    assert_eq!(reply["payload"]["prefix"], "probe/");
    let steps: Vec<&str> = reply["payload"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["step"].as_str())
        .collect();
    assert_eq!(steps, ["authenticate", "put", "get", "delete"]);
    let probe_dir = fix.vtc.data_dir().join("room-blobs").join("probe");
    let left: Vec<_> = std::fs::read_dir(&probe_dir)
        .map(|d| d.collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "a canary was left behind");
}

/// The host's authority over rooms is `vtc.rooms.admin`: an administrator without it is
/// refused every task, reads included.
#[tokio::test]
async fn an_administrator_without_vtc_rooms_admin_is_refused() {
    let fix = fixture().await;
    let m = seed(&fix, AdminAuthority::for_role(AdminRole::Moderator)).await;
    for (uri, payload) in [
        (LIST, json!({})),
        (GET, json!({ "configId": SEED_CONFIG_ID })),
        (PROBE, json!({ "configId": SEED_CONFIG_ID })),
    ] {
        let reply = send(&fix, &m, uri, payload).await;
        assert_eq!(
            tt_error_code(&reply),
            Some("permissionDenied"),
            "{uri}: {reply}"
        );
    }
}

// ─── declared codes ──────────────────────────────────────────────────────

#[tokio::test]
async fn vtc_storage_configs_list_refuses_a_foreign_cursor() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let reply = send(&fix, &a, LIST, json!({ "cursor": "not-ours" })).await;
    assert_eq!(tt_error_code(&reply), Some(LIST_INVALID_CURSOR), "{reply}");
}

#[tokio::test]
async fn vtc_storage_configs_get_answers_not_found() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let reply = send(&fix, &a, GET, json!({ "configId": "nowhere" })).await;
    assert_eq!(tt_error_code(&reply), Some(GET_NOT_FOUND), "{reply}");
}

#[tokio::test]
async fn vtc_storage_configs_probe_answers_not_found() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let reply = send(&fix, &a, PROBE, json!({ "configId": "nowhere" })).await;
    assert_eq!(tt_error_code(&reply), Some(PROBE_NOT_FOUND), "{reply}");
}

/// `create`'s declared codes, each refused before anyone is asked for a gesture.
#[tokio::test]
async fn vtc_storage_configs_create_refuses_with_its_declared_codes() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let create = |id: &str, settings: Value, auth: Option<Value>| {
        let mut p = json!({ "id": id, "label": id, "settings": settings, "reason": "test" });
        if let Some(auth) = auth {
            p["auth"] = auth;
        }
        p
    };

    let reply = send(
        &fix,
        &a,
        CREATE,
        create(SEED_CONFIG_ID, local(&root(&fix, "x")), None),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(CREATE_EXISTS), "{reply}");

    // Outside the operator's bases: the console cannot point the service at the machine.
    let reply = send(&fix, &a, CREATE, create("etc", local("/etc/vtc"), None)).await;
    assert_eq!(
        tt_error_code(&reply),
        Some(CREATE_INVALID_SETTINGS),
        "{reply}"
    );
    assert_eq!(
        reply["payload"]["details"]["member"], "settings.root",
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        CREATE,
        create(
            "amb",
            local(&root(&fix, "amb")),
            Some(json!({ "mode": "ambient" })),
        ),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(CREATE_AUTH_NOT_ALLOWED),
        "{reply}"
    );
    assert!(
        actions_of_kind(&fix, "storage.config.create")
            .await
            .is_empty()
    );
}

/// `update`'s declared codes.
#[tokio::test]
async fn vtc_storage_configs_update_refuses_with_its_declared_codes() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    stored(&fix, "eu", "active").await;
    stored(&fix, "old", "retired").await;

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "nowhere", "label": "x", "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(UPDATE_NOT_FOUND), "{reply}");

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({
            "configId": "eu",
            "settings": { "kind": "s3", "region": "eu-west-1", "bucket": "community-files" },
            "reason": "x",
        }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_KIND_IMMUTABLE),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "eu", "settings": local("/etc/vtc"), "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_INVALID_SETTINGS),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "eu", "auth": { "mode": "ambient" }, "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_AUTH_NOT_ALLOWED),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "old", "capacityBytes": 5, "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(UPDATE_NOT_ACTIVE), "{reply}");

    // A blob is found by the root it was written under: the root cannot move under it.
    blob_on(&fix, "eu").await;
    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "eu", "settings": local(&root(&fix, "eu2")), "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_LOCATION_IMMUTABLE),
        "{reply}"
    );
    assert_eq!(
        reply["payload"]["details"]["members"],
        json!(["settings.root"]),
        "{reply}"
    );
}

/// `retire`'s declared codes.
#[tokio::test]
async fn vtc_storage_configs_retire_refuses_with_its_declared_codes() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;

    let reply = send(
        &fix,
        &a,
        RETIRE,
        json!({ "configId": "nowhere", "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(RETIRE_NOT_FOUND), "{reply}");

    let reply = send(
        &fix,
        &a,
        RETIRE,
        json!({ "configId": SEED_CONFIG_ID, "reason": "x" }),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(RETIRE_IS_DEFAULT), "{reply}");

    stored(&fix, "eu", "active").await;
    let room = hosted_room(&fix).await;
    {
        let _guard = fix.vtc.state.room_storage.lock().await;
        fix.vtc
            .state
            .room_storage
            .write_assignment(&room, "eu", "did:key:zAdmin")
            .await
            .unwrap();
    }
    let reply = send(&fix, &a, RETIRE, json!({ "configId": "eu", "reason": "x" })).await;
    assert_eq!(
        tt_error_code(&reply),
        Some(RETIRE_ROOMS_ASSIGNED),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["rooms"], 1, "{reply}");
}

/// `assign`'s declared codes.
#[tokio::test]
async fn vtc_rooms_storage_assign_refuses_with_its_declared_codes() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let room = hosted_room(&fix).await;
    stored(&fix, "old", "retired").await;

    let reply = send(
        &fix,
        &a,
        ASSIGN,
        json!({ "roomId": "did:key:zNoSuchRoom", "configId": SEED_CONFIG_ID, "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(ASSIGN_ROOM_NOT_FOUND),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        ASSIGN,
        json!({ "roomId": room, "configId": "nowhere", "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(ASSIGN_CONFIG_NOT_FOUND),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        ASSIGN,
        json!({ "roomId": room, "configId": "old", "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(ASSIGN_CONFIG_NOT_ACTIVE),
        "{reply}"
    );
}
