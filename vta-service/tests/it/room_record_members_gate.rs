//! The SDK's writer gate for the record members a room's profile governs
//! (`VtaClient::room_check_record_members`, trust-tasks-tf #1027), driven through the
//! in-process transport: which tasks it sends, what it refuses before anything is sealed,
//! and that a profile read in the room's current epoch is relied on until the epoch moves.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vta_sdk::client::loopback::LoopbackSink;
use vta_sdk::error::VtaError;
use vta_sdk::trust_tasks::{TASK_ROOMS_KEYS_LIST_0_2, TASK_ROOMS_KEYS_PROFILE_READ_0_1};

const ROOM: &str = "did:webvh:Qm:example.com:rooms:northwind";
const HOST: &str = "did:web:host.example";
const MEMBER: &str = "did:webvh:Qm:example.com:people:alice";

/// A VTA holding the room at `epoch`, whose profile lists `listed`.
struct Vta {
    epoch: Mutex<u64>,
    listed: Value,
    seen: Mutex<Vec<String>>,
}

impl Vta {
    fn sent(&self, task: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.as_str() == task)
            .count()
    }
}

impl LoopbackSink for Vta {
    fn dispatch(&self, type_uri: &str, _payload: &Value) -> Result<Value, VtaError> {
        self.seen.lock().unwrap().push(type_uri.to_string());
        if type_uri == TASK_ROOMS_KEYS_LIST_0_2 {
            let epoch = *self.epoch.lock().unwrap();
            return Ok(json!({ "rooms": [{
                "roomId": ROOM, "member": MEMBER, "epoch": epoch, "earliestReadableEpoch": 1,
            }] }));
        }
        if type_uri == TASK_ROOMS_KEYS_PROFILE_READ_0_1 {
            let mut profile = json!({ "name": "Northwind" });
            if !self.listed.is_null() {
                profile["recordMembers"] = self.listed.clone();
            }
            return Ok(json!({
                "roomId": ROOM, "status": "found", "profile": profile,
                "author": MEMBER, "issuedAt": "2026-01-01T00:00:00Z", "version": 3,
                "epoch": *self.epoch.lock().unwrap(), "stale": false,
                "searched": { "fromEpoch": 1, "toEpoch": 1 },
                "verification": { "trace": "verified", "priorRoots": "agree", "anchor": "notChecked" },
            }));
        }
        Err(VtaError::Other(format!("not expected here: {type_uri}")))
    }
}

fn vta(listed: Value) -> (Arc<Vta>, VtaClient) {
    let sink = Arc::new(Vta {
        epoch: Mutex::new(4),
        listed,
        seen: Mutex::new(Vec::new()),
    });
    let client = VtaClient::loopback(sink.clone());
    (sink, client)
}

/// A member the profile does not list is refused, typed, before anything is sealed — and
/// the refusal names what the profile does list.
#[tokio::test]
async fn the_sdk_gate_refuses_a_member_the_profile_does_not_list() {
    let (_, client) = vta(json!(["kind"]));
    let err = client
        .room_check_record_members(
            ROOM,
            HOST,
            None,
            &json!({ "body": "hi", "kind": "message", "inReplyTo": { "key": "msg-1" } }),
        )
        .await
        .unwrap_err();
    match err {
        VtaError::RecordMembersNotPermitted {
            room_id,
            refused,
            listed,
            unresolved,
        } => {
            assert_eq!(room_id, ROOM);
            assert_eq!(refused, vec!["inReplyTo".to_string()]);
            assert_eq!(listed, vec!["kind".to_string()]);
            assert!(unresolved.is_none());
        }
        other => panic!("{other:?}"),
    }
}

/// A listed member is allowed; a body using none of them never reads the profile; and the
/// profile read in the room's current epoch is relied on until the epoch moves.
#[tokio::test]
async fn the_sdk_gate_allows_a_listed_member_once_per_epoch() {
    let (sink, client) = vta(json!(["kind", "inReplyTo", "writtenAt"]));
    client
        .room_check_record_members(ROOM, HOST, None, &json!({ "body": "plain" }))
        .await
        .unwrap();
    assert_eq!(
        sink.sent(TASK_ROOMS_KEYS_PROFILE_READ_0_1),
        0,
        "nothing to check"
    );

    let reply = json!({ "body": "yes", "kind": "message", "inReplyTo": { "key": "msg-1" } });
    client
        .room_check_record_members(ROOM, HOST, None, &reply)
        .await
        .unwrap();
    client
        .room_check_record_members(ROOM, HOST, None, &reply)
        .await
        .unwrap();
    assert_eq!(
        sink.sent(TASK_ROOMS_KEYS_PROFILE_READ_0_1),
        1,
        "relied on within the epoch"
    );

    *sink.epoch.lock().unwrap() = 5;
    client
        .room_check_record_members(ROOM, HOST, None, &reply)
        .await
        .unwrap();
    assert_eq!(
        sink.sent(TASK_ROOMS_KEYS_PROFILE_READ_0_1),
        2,
        "read again once the room's epoch moved"
    );
}

/// No `recordMembers` at all permits none.
#[tokio::test]
async fn a_profile_listing_nothing_permits_nothing() {
    let (_, client) = vta(Value::Null);
    let err = client
        .room_check_record_members(ROOM, HOST, None, &json!({ "kind": "note" }))
        .await
        .unwrap_err();
    assert!(
        matches!(err, VtaError::RecordMembersNotPermitted { ref listed, .. } if listed.is_empty()),
        "{err:?}"
    );
}

/// The SDK keeps its own copy of the governed member names (it sits below `vti-rooms`):
/// it must be the rooms crate's.
#[test]
fn the_sdk_governs_exactly_the_members_vti_rooms_does() {
    assert_eq!(
        vta_sdk::client::RECORD_BODY_MEMBERS,
        vti_rooms::record_members::BODY_MEMBERS
    );
    assert_eq!(
        vta_sdk::client::RECORD_FILE_MEMBERS,
        vti_rooms::record_members::FILE_MEMBERS
    );
    assert_eq!(
        vta_sdk::client::RECORD_KIND_VALUES,
        vti_rooms::record_members::KIND_VALUES
    );
    assert_eq!(
        vta_sdk::client::MEMBER_PROFILE_KIND,
        vti_rooms::member_profile::KIND
    );
    for body in [
        json!({ "kind": "memberProfile", "title": "Alice" }),
        json!({ "kind": "x", "file": { "width": 1, "preview": {} } }),
        json!({ "editedAt": "x", "writtenAt": "y", "inReplyTo": {} }),
        json!({ "body": "none" }),
    ] {
        let obj = body.as_object().unwrap();
        assert_eq!(
            vta_sdk::client::record_members_used(obj),
            vti_rooms::record_members::used(obj)
        );
    }
}
