//! Ambient and sealed storage authentication (trust-tasks-tf #866):
//! `vtc/storage/configs/{list,get,create,update}/0.2` and
//! `vtc/storage/credentials/set/0.2`, driven through the signed-document door as an
//! administrator's client does.
//!
//! What is held here: each version is answered at its own version; `ambient` and
//! `sealed` exist only where the host's `[rooms.files.auth]` permits them
//! (`create/0.2` item 9); a sealed credential is opened only with the community's key,
//! checked as received, kept encrypted, reported by a keyed fingerprint and never
//! returned or audited; and it goes when the config's `auth` leaves `sealed`.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vta_sdk::sealed_transfer::{
    AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1,
    StorageCredentialPayload, armor, bundle_digest_multibase, seal_payload,
};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::config::StorageAuthHostConfig;
use vtc_service::rooms::storage_configs::codes::*;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc, test_community_x25519_public};

use crate::common::second_party::Gesturer;
use crate::common::signed::{error_code, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST_1: &str = "https://trusttasks.org/spec/vtc/storage/configs/list/0.1";
const GET_1: &str = "https://trusttasks.org/spec/vtc/storage/configs/get/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/storage/configs/list/0.2";
const GET: &str = "https://trusttasks.org/spec/vtc/storage/configs/get/0.2";
const CREATE: &str = "https://trusttasks.org/spec/vtc/storage/configs/create/0.2";
const UPDATE: &str = "https://trusttasks.org/spec/vtc/storage/configs/update/0.2";
const SET: &str = "https://trusttasks.org/spec/vtc/storage/credentials/set/0.2";

const ROLE: &str = "arn:aws:iam::123456789012:role/northwind-rooms-writer";
const SECRET: &str = "example-secret-not-a-real-one";

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture(auth: StorageAuthHostConfig) -> Fixture {
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .with_storage_auth(auth)
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

fn permits(ambient: bool, sealed: bool) -> StorageAuthHostConfig {
    StorageAuthHostConfig {
        ambient,
        sealed,
        ..Default::default()
    }
}

async fn admin(fix: &Fixture) -> Party {
    let p = Party::new();
    let admin = AdminAuthority::community_admin();
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
        group_grants: Vec::new(),
        label_set_by_subject: false,
        suspension: None,
    };
    store_acl_entry(&fix.vtc.state.acl_ks, &row).await.unwrap();
    p
}

async fn requester(fix: &mut Fixture) -> Party {
    let p = admin(fix).await;
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

fn s3() -> Value {
    json!({ "kind": "s3", "region": "eu-west-1", "bucket": "northwind-rooms-eu" })
}

/// An R2-style bucket a sealed key presigns for. The endpoint is never reached here.
fn r2() -> Value {
    json!({
        "kind": "s3", "region": "auto", "bucket": "northwind-archive",
        "endpoint": "https://account.r2.cloudflarestorage.com", "pathStyle": true,
    })
}

/// A config stored directly, as an executed create leaves it.
async fn stored(fix: &Fixture, id: &str, settings: Value, auth: Value) {
    let record = json!({
        "id": id,
        "label": id,
        "settings": settings,
        "auth": auth,
        "state": "active",
        "createdBy": "did:key:zAdmin",
        "createdAt": chrono::Utc::now().to_rfc3339(),
    });
    let _guard = fix.vtc.state.room_storage.lock().await;
    fix.vtc.state.room_storage.put_config(record).await.unwrap();
}

fn s3_credential(config: &str) -> Value {
    json!({
        "kind": "s3",
        "configId": config,
        "accessKeyId": "EXAMPLEKEYID0001",
        "secretAccessKey": SECRET,
    })
}

/// `cleartext`, sealed to the community as an administrator's client seals it.
async fn sealed_to_community(cleartext: Value) -> (String, String) {
    let mut id = [0u8; 16];
    rand::fill(&mut id);
    let bundle = seal_payload(
        &test_community_x25519_public(),
        id,
        ProducerAssertion {
            producer_did: "did:key:zAdmin".into(),
            proof: AssertionProof::PinnedOnly,
        },
        &SealedPayloadV1::StorageCredential(Box::new(StorageCredentialPayload(cleartext))),
        &InMemoryNonceStore::new(),
    )
    .await
    .unwrap();
    (armor::encode(&bundle), bundle_digest_multibase(&bundle))
}

async fn set_payload(config: &str, cleartext: Value) -> Value {
    let (sealed, digest) = sealed_to_community(cleartext).await;
    json!({ "configId": config, "sealed": sealed, "digestMultibase": digest, "reason": "evaluation" })
}

async fn audit_text(fix: &Fixture) -> String {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn action_text(fix: &Fixture) -> String {
    fix.vtc
        .state
        .admin_actions_ks
        .prefix_iter_raw(b"action:".to_vec())
        .await
        .unwrap()
        .into_iter()
        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── the flows ───────────────────────────────────────────────────────────

/// On a host permitting `ambient`, a config naming the role it assumes lands on
/// approval; 0.2 readers see the role, 0.1 readers the config without it (0.1's
/// `ambient` is closed).
#[tokio::test]
async fn an_ambient_config_names_its_role_and_a_0_1_reader_is_answered_in_0_1s_shape() {
    let mut fix = fixture(permits(true, false)).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        CREATE,
        json!({
            "id": "eu-s3-instance",
            "label": "EU — S3 (instance role)",
            "settings": s3(),
            "auth": { "mode": "ambient", "roleArn": ROLE },
            "reason": "the community runs in the bucket's account",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        reply["type"].as_str().unwrap().starts_with(CREATE),
        "{reply}"
    );
    assert_eq!(reply["payload"]["config"]["auth"]["roleArn"], ROLE);

    let got = send(&fix, &a, GET, json!({ "configId": "eu-s3-instance" })).await;
    assert_eq!(got["payload"]["config"]["auth"]["roleArn"], ROLE, "{got}");
    assert_eq!(got["payload"]["facts"]["credential"]["status"], "ambient");
    assert_eq!(
        got["payload"]["facts"]["credential"]["roomsHoldingCredentials"],
        0
    );

    let old = send(&fix, &a, GET_1, json!({ "configId": "eu-s3-instance" })).await;
    assert!(old["type"].as_str().unwrap().starts_with(GET_1), "{old}");
    assert_eq!(
        old["payload"]["config"]["auth"],
        json!({ "mode": "ambient" })
    );
    let old = send(&fix, &a, LIST_1, json!({ "kind": "s3" })).await;
    assert!(
        old["payload"]["items"][0]["config"]["auth"]
            .get("roleArn")
            .is_none(),
        "{old}"
    );
}

/// A host that no longer permits a mode keeps the config, reports it `notAllowed` at
/// 0.2 (`required`, never usable, at 0.1), and accepts an update moving it to a
/// permitted mode (`update/0.2` item 8).
#[tokio::test]
async fn a_mode_the_host_withdrew_reads_not_allowed_and_can_be_moved_off() {
    let mut fix = fixture(permits(false, false)).await;
    stored(
        &fix,
        "eu-amb",
        s3(),
        json!({ "mode": "ambient", "roleArn": ROLE }),
    )
    .await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;

    let got = send(&fix, &a, GET, json!({ "configId": "eu-amb" })).await;
    assert_eq!(
        got["payload"]["facts"]["credential"],
        json!({ "status": "notAllowed" }),
        "{got}"
    );
    let listed = send(&fix, &a, LIST_1, json!({})).await;
    let item = listed["payload"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["config"]["id"] == "eu-amb")
        .unwrap()
        .clone();
    assert_eq!(item["facts"]["credential"]["status"], "required", "{item}");

    // A label alone is accepted on a config whose mode is withdrawn.
    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        UPDATE,
        json!({ "configId": "eu-amb", "label": "EU (old)", "reason": "renamed" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["config"]["label"], "EU (old)");
}

/// The whole sealed path: a credential sealed to the community is set through the
/// action list, stored encrypted, reported by fingerprint; it never comes back through
/// any task, the audit trail or the parked action once closed; and it goes when the
/// config's `auth` leaves `sealed`.
#[tokio::test]
async fn a_sealed_credential_is_set_through_consent_and_never_returned_or_audited() {
    let mut fix = fixture(permits(true, true)).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    stored(&fix, "r2-archive", r2(), json!({ "mode": "sealed" })).await;

    let before = send(&fix, &a, GET, json!({ "configId": "r2-archive" })).await;
    assert_eq!(
        before["payload"]["facts"]["credential"],
        json!({ "status": "required" })
    );

    let payload = set_payload("r2-archive", s3_credential("r2-archive")).await;
    let (status, reply) = through(&mut fix, &a, &[&b], SET, payload).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let state = &reply["payload"]["credentialState"];
    assert_eq!(state["status"], "sealed", "{reply}");
    let fingerprint = state["fingerprint"].as_str().unwrap().to_string();
    assert!(state["setAt"].is_string());
    // Probed with the new credential; the store is unreachable here, so not ok — but
    // reported.
    assert!(reply["payload"]["probeOk"].is_boolean(), "{reply}");
    assert!(!reply.to_string().contains(SECRET));

    let got = send(&fix, &a, GET, json!({ "configId": "r2-archive" })).await;
    assert_eq!(
        got["payload"]["facts"]["credential"]["fingerprint"],
        fingerprint
    );
    assert!(!got.to_string().contains(SECRET), "{got}");
    assert!(!audit_text(&fix).await.contains(SECRET), "audited");
    assert!(audit_text(&fix).await.contains(&fingerprint));
    let actions = action_text(&fix).await;
    assert!(
        !actions.contains("BEGIN VTA SEALED BUNDLE"),
        "the closed action still holds the sealed block"
    );

    // `auth` leaves `sealed`: the credential is destroyed.
    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        UPDATE,
        json!({ "configId": "r2-archive", "settings": s3(), "auth": { "mode": "ambient" }, "reason": "the instance role now" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let sealed = fix.vtc.state.room_storage.sealed_credentials().unwrap();
    assert!(sealed.get("r2-archive").await.unwrap().is_none());
}

// ─── declared codes ──────────────────────────────────────────────────────

#[tokio::test]
async fn vtc_storage_configs_list_v0_2_refuses_a_foreign_cursor() {
    let fix = fixture(permits(false, false)).await;
    let a = admin(&fix).await;
    let reply = send(&fix, &a, LIST, json!({ "cursor": "not-ours" })).await;
    assert_eq!(
        tt_error_code(&reply),
        Some(LIST_V0_2_INVALID_CURSOR),
        "{reply}"
    );
}

#[tokio::test]
async fn vtc_storage_configs_get_v0_2_answers_not_found() {
    let fix = fixture(permits(false, false)).await;
    let a = admin(&fix).await;
    let reply = send(&fix, &a, GET, json!({ "configId": "nowhere" })).await;
    assert_eq!(tt_error_code(&reply), Some(GET_V0_2_NOT_FOUND), "{reply}");
}

/// `create/0.2`'s codes, and `authNotAllowed`'s three reasons, each refused before
/// anyone is asked for a gesture.
#[tokio::test]
async fn vtc_storage_configs_create_v0_2_refuses_with_its_declared_codes() {
    let fix = fixture(permits(false, false)).await;
    let a = admin(&fix).await;
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
        create("local", json!({ "kind": "local", "root": "/x/y" }), None),
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(CREATE_V0_2_EXISTS), "{reply}");

    let reply = send(
        &fix,
        &a,
        CREATE,
        create("etc", json!({ "kind": "local", "root": "/etc/vtc" }), None),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(CREATE_V0_2_INVALID_SETTINGS),
        "{reply}"
    );

    for (settings, auth, reason) in [
        (s3(), None, "doesNotFitKind"),
        (
            json!({ "kind": "gcs", "bucket": "northwind-rooms" }),
            Some(json!({ "mode": "ambient", "roleArn": ROLE })),
            "roleArnNotApplicable",
        ),
        (s3(), Some(json!({ "mode": "ambient" })), "disabledByHost"),
        (s3(), Some(json!({ "mode": "sealed" })), "disabledByHost"),
    ] {
        let reply = send(&fix, &a, CREATE, create("amb", settings, auth)).await;
        assert_eq!(
            tt_error_code(&reply),
            Some(CREATE_V0_2_AUTH_NOT_ALLOWED),
            "{reply}"
        );
        assert_eq!(
            reply["payload"]["details"],
            json!({ "reason": reason }),
            "{reply}"
        );
    }
}

/// `update/0.2`'s codes.
#[tokio::test]
async fn vtc_storage_configs_update_v0_2_refuses_with_its_declared_codes() {
    let fix = fixture(permits(false, false)).await;
    let a = admin(&fix).await;
    stored(&fix, "eu-amb", s3(), json!({ "mode": "ambient" })).await;

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "nowhere", "label": "x", "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_V0_2_NOT_FOUND),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "local", "settings": s3(), "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_V0_2_KIND_IMMUTABLE),
        "{reply}"
    );

    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "local", "settings": { "kind": "local", "root": "/etc/vtc" }, "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_V0_2_INVALID_SETTINGS),
        "{reply}"
    );

    // Its mode is withdrawn: changing its settings under that mode is refused, naming why.
    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "eu-amb", "capacityBytes": 5, "settings": { "kind": "s3", "region": "eu-west-2", "bucket": "other" }, "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_V0_2_AUTH_NOT_ALLOWED),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["reason"], "disabledByHost");

    // Retired: only the label changes.
    {
        let mut rec = fix
            .vtc
            .state
            .room_storage
            .config("eu-amb")
            .await
            .unwrap()
            .unwrap();
        rec["state"] = json!("retired");
        fix.vtc.state.room_storage.put_config(rec).await.unwrap();
    }
    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "eu-amb", "capacityBytes": 5, "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_V0_2_NOT_ACTIVE),
        "{reply}"
    );
}

/// A blob is found where it was written: the bucket cannot move under it.
#[tokio::test]
async fn vtc_storage_configs_update_v0_2_refuses_to_move_a_config_holding_blobs() {
    let fix = fixture(permits(true, false)).await;
    let a = admin(&fix).await;
    stored(&fix, "eu-amb", s3(), json!({ "mode": "ambient" })).await;
    let entry = json!({
        "roomId": "did:key:zSomeRoom",
        "blobRef": "zQmBlob",
        "size": 10,
        "manifest": {},
        "configId": "eu-amb",
        "backendRef": { "kind": "s3", "key": "rooms/x/zQmBlob" },
        "state": "committed",
        "refs": 1,
        "committedAt": 0,
    });
    fix.vtc
        .state
        .room_files
        .index_keyspace()
        .insert("blob:test:eu-amb", &entry)
        .await
        .unwrap();
    let reply = send(
        &fix,
        &a,
        UPDATE,
        json!({ "configId": "eu-amb", "settings": { "kind": "s3", "region": "eu-west-1", "bucket": "elsewhere" }, "reason": "x" }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(UPDATE_V0_2_LOCATION_IMMUTABLE),
        "{reply}"
    );
}

/// `credentials/set/0.2`'s codes: the host's permission first, before anything is
/// opened; then the config; then the block.
#[tokio::test]
async fn vtc_storage_credentials_set_refuses_with_its_declared_codes() {
    let off = fixture(permits(false, false)).await;
    let a = admin(&off).await;
    stored(&off, "r2-archive", r2(), json!({ "mode": "sealed" })).await;
    let reply = send(
        &off,
        &a,
        SET,
        set_payload("r2-archive", s3_credential("r2-archive")).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(SET_AUTH_NOT_ALLOWED), "{reply}");

    let fix = fixture(permits(true, true)).await;
    let a = admin(&fix).await;
    stored(&fix, "r2-archive", r2(), json!({ "mode": "sealed" })).await;
    stored(&fix, "eu-amb", s3(), json!({ "mode": "ambient" })).await;

    let reply = send(
        &fix,
        &a,
        SET,
        set_payload("nowhere", s3_credential("nowhere")).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(SET_NOT_FOUND), "{reply}");

    let reply = send(
        &fix,
        &a,
        SET,
        set_payload("eu-amb", s3_credential("eu-amb")).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(SET_NOT_SEALED_MODE), "{reply}");

    // Its digest is not the block's.
    let mut p = set_payload("r2-archive", s3_credential("r2-archive")).await;
    p["digestMultibase"] =
        set_payload("r2-archive", s3_credential("r2-archive")).await["digestMultibase"].clone();
    let reply = send(&fix, &a, SET, p).await;
    assert_eq!(tt_error_code(&reply), Some(SET_CANNOT_OPEN), "{reply}");

    // Sealed for another config: refused, and never quoted back.
    let reply = send(
        &fix,
        &a,
        SET,
        set_payload("r2-archive", s3_credential("another-config")).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(SET_INVALID_CREDENTIAL),
        "{reply}"
    );
    assert!(!reply.to_string().contains(SECRET));
    assert!(
        fix.vtc
            .state
            .room_storage
            .sealed_credentials()
            .unwrap()
            .get("r2-archive")
            .await
            .unwrap()
            .is_none()
    );
}
