//! What rooms store and may store (`docs/05-design-notes/data-rooms-files.md` §6.2–6.3):
//! `vtc/rooms/get/0.1`, `vtc/rooms/usage/0.1` and `vtc/rooms/limits/set/0.1`, driven
//! through the signed-document door as the console does. Files are put through the
//! community's blob host directly, as a member's upload would leave them.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vti_common::blob_store::sha256_digest_multibase;
use vti_rooms::Visibility;
use vti_rooms::blobs::Manifest;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, AdminRole, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::rooms::storage_configs::SEED_CONFIG_ID;
use vtc_service::rooms::storage_configs::codes::*;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::signed::{error_code, post, signed};

const GET: &str = "https://trusttasks.org/spec/vtc/rooms/get/0.1";
const USAGE: &str = "https://trusttasks.org/spec/vtc/rooms/usage/0.1";
const LIMITS: &str = "https://trusttasks.org/spec/vtc/rooms/limits/set/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/rooms/list/0.1";

const CHUNK: usize = 16_384;
const MEMBER: &str = "did:key:z6MkMemberOfTheRoom";

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

async fn vtc() -> TestVtc {
    TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_signers(true)
        .with_audit(true)
        .build()
        .await
}

async fn seed(vtc: &TestVtc, admin: AdminAuthority) -> Party {
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
    store_acl_entry(&vtc.state.acl_ks, &row).await.unwrap();
    p
}

async fn send(vtc: &TestVtc, by: &Party, uri: &str, payload: Value) -> Value {
    post(vtc, &signed(by, uri, payload).await).await.1
}

/// A hosted room at `visibility`, on the default config.
async fn room(vtc: &TestVtc, visibility: Visibility) -> vti_rooms::Room {
    let room = vti_rooms::Room {
        room_id: format!("did:key:z6MkRoom{}", uuid::Uuid::new_v4().simple()),
        owner_did: "did:key:zOwner".into(),
        visibility,
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
    vti_rooms::storage::create_room(&vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    vtc.state
        .room_storage
        .assign_new_room(&room.room_id)
        .await
        .unwrap();
    room
}

/// A file of `len` bytes uploaded by `MEMBER` and committed, as a member's
/// upload through `rooms/blobs/*` leaves it.
async fn upload(vtc: &TestVtc, room: &vti_rooms::Room, len: usize, seed: u8) -> String {
    let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
    let digest = sha256_digest_multibase(&Sha256::digest(&bytes).into());
    let manifest = Manifest::parse(&json!({
        "size": len,
        "chunks": { "chunkSize": CHUNK, "chunkCount": 1, "chunkDigests": [digest] },
        "digest": digest,
    }))
    .unwrap();
    let files = &vtc.state.room_files;
    let begun = files
        .begin(room, MEMBER, Some(MEMBER), manifest)
        .await
        .unwrap();
    let id = begun.upload_id.to_string();
    files
        .put_chunk(MEMBER, &id, 0, &digest, &bytes)
        .await
        .unwrap();
    files.commit(MEMBER, &id).await.unwrap().blob_ref
}

async fn limits_audit(vtc: &TestVtc) -> Vec<Value> {
    vtc.state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter(|env| env.event.variant_name() == "RoomLimitsChanged")
        .map(|env| serde_json::to_value(&env.event).unwrap())
        .collect()
}

// ─── vtc/rooms/get ───────────────────────────────────────────────────────

/// One room's storage, limits and usage: sizes, configs and a count of members,
/// never a file and never a member's DID.
#[tokio::test]
async fn a_room_is_described_by_sizes_and_counts() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let r = room(&vtc, Visibility::Attributed).await;
    for (len, seed) in [(300, 1), (900, 2), (600, 3)] {
        upload(&vtc, &r, len, seed).await;
    }

    let reply = send(&vtc, &a, GET, json!({ "roomId": r.room_id })).await;
    let p = &reply["payload"];
    assert_eq!(p["room"]["roomId"], r.room_id, "{reply}");
    assert_eq!(p["room"]["visibility"], "attributed");
    assert_eq!(p["storage"]["configId"], SEED_CONFIG_ID);
    assert_eq!(p["storage"]["earlierConfigs"], json!([]));
    assert_eq!(p["usage"]["room"]["files"], 3);
    assert_eq!(p["usage"]["room"]["bytes"], 1800);
    assert_eq!(p["usage"]["orphans"]["files"], 0);
    let sizes: Vec<u64> = p["largestBlobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["size"].as_u64().unwrap())
        .collect();
    assert_eq!(sizes, vec![900, 600, 300]);
    assert_eq!(p["limits"]["roomSource"], "default");
    assert_eq!(p["limits"]["memberSource"], "default");
    assert_eq!(p["membersWithUsage"], 1);
    assert!(
        !reply.to_string().contains(MEMBER),
        "no member DID: {reply}"
    );
}

#[tokio::test]
async fn a_private_room_reports_no_member_count() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let r = room(&vtc, Visibility::Private).await;
    upload(&vtc, &r, 100, 4).await;
    let reply = send(&vtc, &a, GET, json!({ "roomId": r.room_id })).await;
    assert_eq!(reply["payload"]["usage"]["room"]["files"], 1, "{reply}");
    assert!(
        reply["payload"].get("membersWithUsage").is_none(),
        "{reply}"
    );
}

#[tokio::test]
async fn vtc_rooms_get_answers_not_found() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let reply = send(&vtc, &a, GET, json!({ "roomId": "did:key:z6MkNoSuchRoom" })).await;
    assert_eq!(tt_error_code(&reply), Some(ROOM_GET_NOT_FOUND), "{reply}");
}

/// The host's authority over rooms is `vtc.rooms.admin`: an administrator without it
/// is refused every one of these, and now `vtc/rooms/list` too.
#[tokio::test]
async fn an_administrator_without_vtc_rooms_admin_is_refused() {
    let vtc = vtc().await;
    let m = seed(&vtc, AdminAuthority::for_role(AdminRole::Moderator)).await;
    let r = room(&vtc, Visibility::Attributed).await;
    for (uri, payload) in [
        (LIST, json!({})),
        (GET, json!({ "roomId": r.room_id })),
        (USAGE, json!({ "groupBy": "room" })),
        (
            LIMITS,
            json!({ "roomId": r.room_id, "target": { "kind": "room" },
                    "limits": { "maxFiles": 1 }, "reason": "test" }),
        ),
    ] {
        let reply = send(&vtc, &m, uri, payload).await;
        assert_eq!(
            tt_error_code(&reply),
            Some("permissionDenied"),
            "{uri}: {reply}"
        );
    }
}

// ─── vtc/rooms/limits/set ────────────────────────────────────────────────

/// An override replaces its scope, is enforced at the next upload, is audited with its
/// reason, deletes nothing, and clears back to the default.
#[tokio::test]
async fn an_override_is_enforced_audited_and_cleared() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let r = room(&vtc, Visibility::Attributed).await;
    upload(&vtc, &r, 100, 5).await;
    upload(&vtc, &r, 100, 6).await;

    // One member, below what they already hold.
    let reply = send(
        &vtc,
        &a,
        LIMITS,
        json!({
            "roomId": r.room_id,
            "target": { "kind": "member", "member": MEMBER },
            "limits": { "maxFiles": 1 },
            "reason": "Tidy up before adding more."
        }),
    )
    .await;
    let p = &reply["payload"];
    assert_eq!(p["overLimit"], true, "{reply}");
    assert_eq!(p["targetLimits"]["maxFiles"], 1);
    assert_eq!(p["usage"]["files"], 2);
    // Nothing deleted; the next upload refused.
    assert_eq!(
        vtc.state
            .room_files
            .room_usage(&r.room_id)
            .await
            .unwrap()
            .files,
        2
    );
    let (_, manifest) = {
        let bytes = vec![7u8; 10];
        let digest = sha256_digest_multibase(&Sha256::digest(&bytes).into());
        (
            bytes,
            Manifest::parse(&json!({
                "size": 10,
                "chunks": { "chunkSize": CHUNK, "chunkCount": 1, "chunkDigests": [digest] },
                "digest": digest,
            }))
            .unwrap(),
        )
    };
    assert!(
        vtc.state
            .room_files
            .begin(&r, MEMBER, Some(MEMBER), manifest)
            .await
            .is_err()
    );

    let rows = limits_audit(&vtc).await;
    assert_eq!(rows.len(), 1);
    let data = &rows[0]["data"];
    assert_eq!(data["roomId"], r.room_id);
    assert_eq!(data["target"]["member"], MEMBER);
    assert_eq!(data["current"]["limits"]["maxFiles"], 1);
    assert!(data.get("previous").is_none());
    assert_eq!(data["reason"], "Tidy up before adding more.");

    // The room's own limits: its source becomes `override`.
    let reply = send(
        &vtc,
        &a,
        LIMITS,
        json!({ "roomId": r.room_id, "target": { "kind": "room" },
                "limits": { "maxFiles": 50, "maxBytes": 1000000 }, "reason": "small room" }),
    )
    .await;
    assert_eq!(
        reply["payload"]["limits"]["roomSource"], "override",
        "{reply}"
    );
    assert_eq!(reply["payload"]["overLimit"], false);

    // Cleared, both.
    for target in [
        json!({ "kind": "room" }),
        json!({ "kind": "member", "member": MEMBER }),
    ] {
        let reply = send(
            &vtc,
            &a,
            LIMITS,
            json!({ "roomId": r.room_id, "target": target, "clear": true, "reason": "back" }),
        )
        .await;
        assert_eq!(reply["payload"]["overLimit"], false, "{reply}");
    }
    let got = send(&vtc, &a, GET, json!({ "roomId": r.room_id })).await;
    assert_eq!(got["payload"]["limits"]["roomSource"], "default", "{got}");
    assert_eq!(limits_audit(&vtc).await.len(), 4);
}

/// Files off for a room: refused at the next upload, and reported.
#[tokio::test]
async fn files_can_be_turned_off_for_one_room() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let r = room(&vtc, Visibility::Open).await;
    let reply = send(
        &vtc,
        &a,
        LIMITS,
        json!({ "roomId": r.room_id, "target": { "kind": "room" },
                "filesEnabled": false, "reason": "open rooms get no files" }),
    )
    .await;
    assert_eq!(
        reply["payload"]["limits"]["limits"]["filesEnabled"], false,
        "{reply}"
    );
    let got = send(&vtc, &a, GET, json!({ "roomId": r.room_id })).await;
    assert_eq!(got["payload"]["limits"]["limits"]["filesEnabled"], false);
}

#[tokio::test]
async fn vtc_rooms_limits_set_refuses_with_its_declared_codes() {
    // A host ceiling below what the schema allows, so `aboveCeiling` is the host's
    // refusal and not the schema's.
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_signers(true)
        .with_audit(true)
        .with_room_file_ceiling(1024 * 1024)
        .build()
        .await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let r = room(&vtc, Visibility::Attributed).await;
    let private = room(&vtc, Visibility::Private).await;
    let set = |room: &str, target: Value, extra: Value| {
        let mut p = json!({ "roomId": room, "target": target, "reason": "test" });
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };

    let reply = send(
        &vtc,
        &a,
        LIMITS,
        set(
            "did:key:z6MkNoSuchRoom",
            json!({ "kind": "room" }),
            json!({ "clear": true }),
        ),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(LIMITS_NOT_FOUND), "{reply}");

    let reply = send(
        &vtc,
        &a,
        LIMITS,
        set(
            &r.room_id,
            json!({ "kind": "room" }),
            json!({ "limits": { "maxFileBytes": 2 * 1024 * 1024 } }),
        ),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(LIMITS_ABOVE_CEILING), "{reply}");

    let reply = send(
        &vtc,
        &a,
        LIMITS,
        set(
            &private.room_id,
            json!({ "kind": "memberDefault" }),
            json!({ "limits": { "maxFiles": 1 } }),
        ),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(LIMITS_MEMBER_LIMITS_UNAVAILABLE),
        "{reply}"
    );

    for extra in [
        json!({ "clear": true, "limits": { "maxFiles": 1 } }),
        json!({}),
    ] {
        let reply = send(
            &vtc,
            &a,
            LIMITS,
            set(&r.room_id, json!({ "kind": "room" }), extra),
        )
        .await;
        assert_eq!(
            tt_error_code(&reply),
            Some(LIMITS_INVALID_COMBINATION),
            "{reply}"
        );
    }
    let reply = send(
        &vtc,
        &a,
        LIMITS,
        set(
            &r.room_id,
            json!({ "kind": "memberDefault" }),
            json!({ "filesEnabled": false }),
        ),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(LIMITS_INVALID_COMBINATION),
        "{reply}"
    );

    // Item 2: a member target names its member, and no other does.
    let reply = send(
        &vtc,
        &a,
        LIMITS,
        set(
            &r.room_id,
            json!({ "kind": "member" }),
            json!({ "clear": true }),
        ),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some("malformedRequest"), "{reply}");
    assert!(
        limits_audit(&vtc).await.is_empty(),
        "a refusal changes nothing"
    );
}

// ─── vtc/rooms/usage ─────────────────────────────────────────────────────

/// Every grouping, over one room with two files and one download.
#[tokio::test]
async fn usage_is_grouped_by_room_member_config_and_day() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let r = room(&vtc, Visibility::Attributed).await;
    let blob = upload(&vtc, &r, 1000, 7).await;
    upload(&vtc, &r, 500, 8).await;
    let d = vtc
        .state
        .room_files
        .open_download(&r, MEMBER, Some(MEMBER), &blob)
        .await
        .unwrap();
    vtc.state
        .room_files
        .read_chunk(MEMBER, &d.download_id.to_string(), 0)
        .await
        .unwrap();

    let reply = send(&vtc, &a, USAGE, json!({ "groupBy": "room" })).await;
    let items = reply["payload"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{reply}");
    let row = &items[0];
    assert_eq!(row["roomId"], r.room_id);
    assert_eq!(row["storageConfig"], SEED_CONFIG_ID);
    assert_eq!(
        (row["files"].as_u64(), row["bytes"].as_u64()),
        (Some(2), Some(1500))
    );
    assert_eq!(row["uploads"], 2);
    assert_eq!(row["downloads"], 1);
    assert_eq!(row["egressBytes"], 1000);
    assert!(row["limits"]["maxBytes"].is_u64());

    let reply = send(&vtc, &a, USAGE, json!({ "groupBy": "member" })).await;
    let items = reply["payload"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{reply}");
    assert_eq!(items[0]["member"], MEMBER);
    assert_eq!(items[0]["bytes"], 1500);

    let reply = send(&vtc, &a, USAGE, json!({ "groupBy": "storageConfig" })).await;
    let local = reply["payload"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["storageConfig"] == SEED_CONFIG_ID)
        .cloned()
        .expect("the local config");
    assert_eq!(local["files"], 2, "{reply}");
    assert_eq!(local["uploads"], 2);

    let reply = send(
        &vtc,
        &a,
        USAGE,
        json!({ "groupBy": "day", "filter": { "roomId": r.room_id } }),
    )
    .await;
    let items = reply["payload"]["items"].as_array().expect("items");
    let today = chrono::Utc::now().date_naive().to_string();
    let last = items.last().expect("a day");
    assert_eq!(last["date"], today, "{reply}");
    assert_eq!(last["files"], 2);
    assert_eq!(last["uploads"], 2);
    assert_eq!(reply["payload"]["to"], today);
}

/// A page, and the cursor that continues it.
#[tokio::test]
async fn usage_pages_by_cursor() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    for (len, seed) in [(10, 9), (20, 10), (30, 11)] {
        let r = room(&vtc, Visibility::Open).await;
        upload(&vtc, &r, len, seed).await;
    }
    let first = send(&vtc, &a, USAGE, json!({ "groupBy": "room", "limit": 2 })).await;
    let p = &first["payload"];
    let bytes: Vec<u64> = p["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["bytes"].as_u64().unwrap())
        .collect();
    assert_eq!(bytes, vec![30, 20], "largest first: {first}");
    let cursor = p["nextCursor"].as_str().expect("more remain").to_string();
    let rest = send(
        &vtc,
        &a,
        USAGE,
        json!({ "groupBy": "room", "limit": 2, "cursor": cursor }),
    )
    .await;
    assert_eq!(rest["payload"]["items"][0]["bytes"], 10, "{rest}");
    assert!(rest["payload"].get("nextCursor").is_none());
}

#[tokio::test]
async fn vtc_rooms_usage_refuses_with_its_declared_codes() {
    let vtc = vtc().await;
    let a = seed(&vtc, AdminAuthority::community_admin()).await;
    let private = room(&vtc, Visibility::Private).await;
    upload(&vtc, &private, 10, 12).await;

    for filter in [
        json!({ "from": "2026-10-10", "to": "2026-10-01" }),
        json!({ "from": "2024-01-01", "to": "2026-01-01" }),
        json!({ "from": "2001-01-01", "to": "2001-01-02" }),
    ] {
        let reply = send(
            &vtc,
            &a,
            USAGE,
            json!({ "groupBy": "room", "filter": filter }),
        )
        .await;
        assert_eq!(tt_error_code(&reply), Some(USAGE_INVALID_RANGE), "{reply}");
    }

    let reply = send(
        &vtc,
        &a,
        USAGE,
        json!({ "groupBy": "member", "filter": { "roomId": private.room_id } }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(USAGE_MEMBER_USAGE_UNAVAILABLE),
        "{reply}"
    );

    // A cursor from another query, and one never issued.
    for cursor in ["vtc-rooms-usage:0000000000000000:1", "not-ours"] {
        let reply = send(
            &vtc,
            &a,
            USAGE,
            json!({ "groupBy": "room", "cursor": cursor }),
        )
        .await;
        assert_eq!(tt_error_code(&reply), Some(USAGE_INVALID_CURSOR), "{reply}");
    }
}
