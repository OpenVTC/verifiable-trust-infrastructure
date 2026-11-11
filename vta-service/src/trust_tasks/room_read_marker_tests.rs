//! `rooms/keys/read-marker/set/0.1`, `rooms/keys/read-marker/moved/0.1` and
//! `rooms/keys/list/0.3` — one test per rule (trust-tasks-tf #1086).

use std::time::Duration;

use super::*;
use crate::operations::persona::test_fixture::{self as personas, Persona};
use crate::operations::room_groups::Member;
use crate::operations::room_key_watch::RoomKeyWatches;
use serde_json::json;
use trust_tasks_rs::TypeUri;

const ROOM: &str = "did:webvh:example.com:rooms:northwind";
const OTHER_ROOM: &str = "did:webvh:example.com:rooms:bookclub";
const HOST: &str = "did:web:rooms.example.com";
const MEDIATOR: &str = "did:example:mediator";
const SET: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_MARKER_SET_0_1;
const MOVED: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_MARKER_MOVED_0_1;
const LIST_0_2: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_LIST_0_2;
const LIST_0_3: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_LIST_0_3;

/// Alice's two devices and Bob's one, each a client of its person's own context.
const ALICE_PHONE: &str = "did:key:z6MkAlicePhoneExample";
const ALICE_LAPTOP: &str = "did:key:z6MkAliceLaptopExample";
const BOB_PHONE: &str = "did:key:z6MkBobPhoneExample";
const ALICE_AGENT: &str = "did:key:z6MkAliceAgentExample";

/// A `createdAt` no log or audit row may carry.
const SEEN_AT: &str = "2027-02-01T10:14:02.123+01:00";

fn request(uri: &str, payload: Value) -> TrustTask<Value> {
    let uri: TypeUri = uri.parse().unwrap();
    TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
}

fn body(outcome: TrustTaskOutcome) -> Value {
    serde_json::from_slice(&outcome.body).expect("the outcome is a document")
}

fn code(doc: &Value) -> String {
    doc["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn client(did: &str, context: &str) -> AuthClaims {
    AuthClaims {
        did: did.into(),
        ..crate::test_support::admin_claims_for_context(context)
    }
}

struct Fixture {
    state: AppState,
    _dir: tempfile::TempDir,
    alice: Persona,
    bob: Persona,
}

/// One VTA serving alice and bob, each a persona in their own context with a client entry
/// per device; alice's persona holds [`ROOM`] and [`OTHER_ROOM`], bob's [`ROOM`]. A mediator
/// is configured, so the VTA can push to its clients.
async fn fixture() -> Fixture {
    let (state, dir) = crate::test_support::build_signing_test_app_state().await;
    for (id, name) in [("alice", "Alice"), ("bob", "Bob")] {
        crate::contexts::create_context(&state.contexts_ks, id, name)
            .await
            .expect("create context");
    }
    let persona = |context: &'static str, key: &'static str| {
        let state = &state;
        async move {
            personas::did_key_persona(
                &state.keys_ks,
                &state.internal_ks,
                &state.contexts_ks,
                &state.acl_ks,
                &state.seed_store,
                &state.audit_sink,
                context,
                key,
            )
            .await
        }
    };
    let alice = persona("alice", "alice-key").await;
    let bob = persona("bob", "bob-key").await;
    for (room, did) in [
        (ROOM, &alice.did),
        (OTHER_ROOM, &alice.did),
        (ROOM, &bob.did),
    ] {
        room_groups::create_group(&state.room_groups_ks, &Member::new(room, did).unwrap(), 0)
            .await
            .expect("group state");
    }
    for (did, context) in [
        (ALICE_PHONE, "alice"),
        (ALICE_LAPTOP, "alice"),
        (BOB_PHONE, "bob"),
    ] {
        let mut entry = vti_common::acl::AclEntry::new(did, crate::acl::Role::Admin, "test");
        entry.allowed_contexts = vec![context.into()];
        crate::acl::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();
    }
    // An agent alice equipped: a delegate.
    let agent: vti_common::acl::AclEntry = serde_json::from_value(json!({
        "did": ALICE_AGENT, "role": "admin", "label": null,
        "allowed_contexts": ["alice"], "created_at": 0, "created_by": "test",
        "kind": { "kind": "service", "serviceKind": "ai-agent" },
    }))
    .unwrap();
    vti_common::acl::store_acl_entry(&state.acl_ks, &agent)
        .await
        .unwrap();
    state.config.write().await.messaging = Some(vti_common::config::MessagingConfig {
        mediator_url: String::new(),
        mediator_did: MEDIATOR.into(),
        mediator_host: None,
        setup_acl: false,
        drain_inbox_on_start: false,
    });
    Fixture {
        state,
        _dir: dir,
        alice,
        bob,
    }
}

fn marker(version: u64, created_at: Option<&str>) -> Value {
    let mut m = json!({ "version": version });
    if let Some(t) = created_at {
        m["createdAt"] = json!(t);
    }
    m
}

async fn set_as(f: &Fixture, caller: &AuthClaims, member: &str, m: Value, rewind: bool) -> Value {
    let mut payload = json!({ "roomId": ROOM, "member": member, "readMarker": m });
    if rewind {
        payload["rewind"] = json!(true);
    }
    body(handle_set(&f.state, caller, request(SET, payload)).await)
}

/// A set by alice's phone, as alice.
async fn set(f: &Fixture, m: Value) -> Value {
    set_as(f, &client(ALICE_PHONE, "alice"), &f.alice.did, m, false).await
}

async fn rewind(f: &Fixture, m: Value) -> Value {
    set_as(f, &client(ALICE_PHONE, "alice"), &f.alice.did, m, true).await
}

/// The response conforms to the generated type, and `(moved, marker)`.
fn answer(doc: &Value) -> (bool, Value) {
    let _: set_spec::Response =
        serde_json::from_value(doc["payload"].clone()).unwrap_or_else(|e| panic!("{e}: {doc}"));
    (
        doc["payload"]["moved"].as_bool().unwrap(),
        doc["payload"]["readMarker"].clone(),
    )
}

async fn list(f: &Fixture, uri: &str, caller: &AuthClaims, payload: Value) -> Value {
    let doc = request(uri, payload);
    let out = if uri == LIST_0_3 {
        super::super::room_label::handle_list_v0_3(&f.state, caller, doc).await
    } else {
        super::super::room_label::handle_list_v0_2(&f.state, caller, doc).await
    };
    body(out)
}

fn entry<'a>(listed: &'a Value, room: &str, member: &str) -> &'a Value {
    listed["payload"]["rooms"]
        .as_array()
        .unwrap_or_else(|| panic!("rooms: {listed}"))
        .iter()
        .find(|e| e["roomId"] == room && e["member"] == member)
        .unwrap_or_else(|| panic!("no entry for {room} as {member}: {listed}"))
}

/// Recipient item 3: forward only — the greater version; at an equal version the later
/// `createdAt`; an absent `createdAt` earlier than any present one.
#[tokio::test]
async fn the_marker_only_moves_forward() {
    let f = fixture().await;
    assert_eq!(
        answer(&set(&f, marker(10, None)).await),
        (true, marker(10, None))
    );
    // Behind: kept as it was, and the answer is the one in force.
    assert_eq!(
        answer(&set(&f, marker(5, None)).await),
        (false, marker(10, None))
    );
    // Equal version, a createdAt where there was none: further on.
    let t1 = "2027-02-01T10:00:00Z";
    assert_eq!(
        answer(&set(&f, marker(10, Some(t1))).await),
        (true, marker(10, Some(t1)))
    );
    // Equal version, absent createdAt: earlier than the present one.
    assert_eq!(
        answer(&set(&f, marker(10, None)).await),
        (false, marker(10, Some(t1)))
    );
    // Equal version, an earlier createdAt: behind.
    assert_eq!(
        answer(&set(&f, marker(10, Some("2027-02-01T09:00:00Z"))).await),
        (false, marker(10, Some(t1)))
    );
    // Equal version, a later createdAt: further on.
    let t2 = "2027-02-01T11:00:00Z";
    assert_eq!(
        answer(&set(&f, marker(10, Some(t2))).await),
        (true, marker(10, Some(t2)))
    );
    // A greater version moves it even with an earlier (or no) createdAt: replaced whole.
    assert_eq!(
        answer(&set(&f, marker(11, None)).await),
        (true, marker(11, None))
    );
}

/// Item 5: `createdAt` is compared as an instant and stored and returned exactly as received.
#[tokio::test]
async fn created_at_is_an_instant_kept_as_written() {
    let f = fixture().await;
    let (moved, m) = answer(&set(&f, marker(3, Some(SEEN_AT))).await);
    assert!(moved);
    assert_eq!(m["createdAt"], SEEN_AT, "returned exactly as received");
    // The same instant spelt in UTC is not further on.
    let (moved, m) = answer(&set(&f, marker(3, Some("2027-02-01T09:14:02.123Z"))).await);
    assert!(!moved);
    assert_eq!(m["createdAt"], SEEN_AT);
    let listed = list(
        &f,
        LIST_0_3,
        &client(ALICE_PHONE, "alice"),
        json!({ "includePersonal": true }),
    )
    .await;
    assert_eq!(
        entry(&listed, ROOM, &f.alice.did)["readMarker"]["createdAt"],
        SEEN_AT,
        "listed exactly as received: {listed}"
    );
}

/// *Definitions* — the order is total, so sets arriving in any order leave the same marker.
#[tokio::test]
async fn sets_in_any_order_converge() {
    let markers = [
        marker(7, Some("2027-02-01T10:00:00Z")),
        marker(9, None),
        marker(9, Some("2027-02-01T09:00:00Z")),
        marker(9, Some("2027-02-01T08:00:00Z")),
        marker(2, Some("2027-02-02T10:00:00Z")),
    ];
    let orders: [[usize; 5]; 4] = [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 0, 4, 1, 3],
        [3, 4, 1, 0, 2],
    ];
    for order in orders {
        let f = fixture().await;
        let mut last = Value::Null;
        for i in order {
            last = answer(&set(&f, markers[i].clone()).await).1;
        }
        assert_eq!(
            last,
            marker(9, Some("2027-02-01T09:00:00Z")),
            "order {order:?}"
        );
    }
}

/// Item 4: a rewind replaces the marker even when it is behind, and is not moved when equal.
#[tokio::test]
async fn a_rewind_marks_unread_and_a_later_set_reads_again() {
    let f = fixture().await;
    set(&f, marker(415, Some("2027-02-01T10:14:02Z"))).await;
    let back = marker(408, Some("2027-02-01T09:58:41Z"));
    assert_eq!(
        answer(&rewind(&f, back.clone()).await),
        (true, back.clone())
    );
    // Equal: nothing written.
    assert_eq!(
        answer(&rewind(&f, back.clone()).await),
        (false, back.clone())
    );
    // The whole room unread.
    assert_eq!(
        answer(&rewind(&f, marker(0, None)).await),
        (true, marker(0, None))
    );
    // And reading again moves it forward from there.
    assert_eq!(
        answer(&set(&f, marker(1, None)).await),
        (true, marker(1, None))
    );
    // `rewind: false` is not accepted, nor is a negative version, an extra member or a
    // marker without a version: the schema refuses them before the handler runs.
    let schema = vti_specs::schema_index::schema_for(SET).expect("set is pinned");
    for bad in [
        json!({ "roomId": ROOM, "member": "did:key:z", "readMarker": marker(1, None), "rewind": false }),
        json!({ "roomId": ROOM, "member": "did:key:z", "readMarker": { "version": -1 } }),
        json!({ "roomId": ROOM, "member": "did:key:z", "readMarker": { "createdAt": SEEN_AT } }),
        json!({ "roomId": ROOM, "member": "did:key:z", "readMarker": { "version": 1, "seenBy": "x" } }),
        json!({ "roomId": ROOM, "readMarker": marker(1, None) }),
    ] {
        assert!(
            trust_tasks_rs::validate::against_schema(schema, &bad).is_err(),
            "{bad}"
        );
    }
}

/// *Retry safety*: the same request again writes nothing and answers `moved: false` with the
/// marker it set.
#[tokio::test]
async fn a_repeat_is_idempotent() {
    let f = fixture().await;
    let m = marker(42, Some(SEEN_AT));
    let first = answer(&set(&f, m.clone()).await);
    let again = answer(&set(&f, m.clone()).await);
    assert_eq!(first, (true, m.clone()));
    assert_eq!(again, (false, m.clone()));
    let first = answer(&rewind(&f, marker(40, None)).await);
    let again = answer(&rewind(&f, marker(40, None)).await);
    assert_eq!(first, (true, marker(40, None)));
    assert_eq!(again, (false, marker(40, None)));
}

/// Item 1: a delegate is `permissionDenied`, and moves nothing.
#[tokio::test]
async fn a_delegate_is_refused() {
    let f = fixture().await;
    set(&f, marker(5, None)).await;
    let out = set_as(
        &f,
        &client(ALICE_AGENT, "alice"),
        &f.alice.did,
        marker(50, None),
        false,
    )
    .await;
    assert_eq!(code(&out), "permissionDenied", "{out}");
    let m = room_groups::read_marker(
        &f.state.room_groups_ks,
        &Member::new(ROOM, &f.alice.did).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(m.version, 5);
    // And lists no marker either.
    let listed = list(
        &f,
        LIST_0_3,
        &client(ALICE_AGENT, "alice"),
        json!({ "includePersonal": true }),
    )
    .await;
    assert_eq!(listed["payload"]["rooms"], json!([]), "{listed}");
}

/// Item 2: one `notHeld` for a room this member does not hold and for a member the caller
/// does not act as — the same answer, and nothing written.
#[tokio::test]
async fn not_held_is_one_answer_for_both_causes() {
    let f = fixture().await;
    // Bob's persona holds ROOM, but alice's phone does not act as it.
    let not_mine = set_as(
        &f,
        &client(ALICE_PHONE, "alice"),
        &f.bob.did,
        marker(9, None),
        false,
    )
    .await;
    // Bob's persona holds no group state for OTHER_ROOM.
    let not_held = body(
        handle_set(
            &f.state,
            &client(BOB_PHONE, "bob"),
            request(
                SET,
                json!({ "roomId": OTHER_ROOM, "member": f.bob.did, "readMarker": marker(9, None) }),
            ),
        )
        .await,
    );
    for out in [&not_mine, &not_held] {
        assert_eq!(code(out), "rooms/keys/read-marker/set:notHeld", "{out}");
    }
    let strip = |doc: &Value| {
        let mut p = doc["payload"].clone();
        p.as_object_mut().unwrap().remove("inResponseTo");
        p
    };
    assert_eq!(strip(&not_mine), strip(&not_held));
    let bobs = Member::new(ROOM, &f.bob.did).unwrap();
    assert!(
        room_groups::read_marker(&f.state.room_groups_ks, &bobs)
            .await
            .unwrap()
            .is_none()
    );
}

/// List 0.3: the marker rides its own entry, and only with `includePersonal`; 0.2 never
/// carries one.
#[tokio::test]
async fn list_0_3_returns_the_marker_only_when_asked() {
    let f = fixture().await;
    set(&f, marker(415, Some(SEEN_AT))).await;
    let alice = client(ALICE_PHONE, "alice");
    let listed = list(&f, LIST_0_3, &alice, json!({ "includePersonal": true })).await;
    let _: vti_specs::rooms::keys::list::v0_3::Response =
        serde_json::from_value(listed["payload"].clone()).unwrap();
    assert_eq!(
        entry(&listed, ROOM, &f.alice.did)["readMarker"],
        marker(415, Some(SEEN_AT))
    );
    assert!(
        entry(&listed, OTHER_ROOM, &f.alice.did)
            .get("readMarker")
            .is_none()
    );
    for payload in [json!({}), json!({ "includePersonal": false })] {
        let listed = list(&f, LIST_0_3, &alice, payload).await;
        assert!(
            entry(&listed, ROOM, &f.alice.did)
                .get("readMarker")
                .is_none(),
            "a marker without includePersonal: {listed}"
        );
    }
    let old = list(&f, LIST_0_2, &alice, json!({ "includePersonal": true })).await;
    assert!(
        entry(&old, ROOM, &f.alice.did).get("readMarker").is_none(),
        "0.2 has no readMarker: {old}"
    );
    // Bob's caller sees bob's entry, without alice's marker.
    let bobs = list(
        &f,
        LIST_0_3,
        &client(BOB_PHONE, "bob"),
        json!({ "includePersonal": true }),
    )
    .await;
    assert!(!bobs.to_string().contains(SEEN_AT), "{bobs}");
}

/// Arm a watch record for `caller`, as `member`, on `room`.
async fn watching(f: &Fixture, caller: &str, member: &str, room: &str) {
    let record = RoomKeyWatches::new_record(
        caller,
        member,
        room,
        HOST,
        MEDIATOR,
        chrono::Utc::now().timestamp() + 3600,
    )
    .unwrap();
    f.state.room_key_watches.put(&record).await.unwrap();
}

/// What the VTA pushed as `moved` so far, as (recipient, document).
fn moved_pushes(f: &Fixture) -> Vec<(String, Value)> {
    crate::messaging::push::take_pushes(&f.state)
        .into_iter()
        .filter(|p| p.body["type"] == MOVED)
        .map(|p| (p.recipient_did, p.body))
        .collect()
}

async fn after_the_window() {
    tokio::time::sleep(MOVED_COALESCE + Duration::from_millis(250)).await;
}

/// `moved` Producer items 1–2: only the member's other clients watching the room as that
/// member — never the setter, another member's clients, a client watching another room, or
/// a delegate — get the room, the member and the marker, and nothing else.
#[tokio::test]
async fn moved_goes_to_the_members_other_watching_clients_only() {
    let f = fixture().await;
    watching(&f, ALICE_PHONE, &f.alice.did, ROOM).await;
    watching(&f, ALICE_LAPTOP, &f.alice.did, ROOM).await;
    watching(&f, BOB_PHONE, &f.bob.did, ROOM).await;
    watching(&f, ALICE_AGENT, &f.alice.did, ROOM).await;
    let held_before = f.state.room_key_watches.all().await.unwrap().len();

    set(&f, marker(415, Some(SEEN_AT))).await;
    after_the_window().await;
    let sent = moved_pushes(&f);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (to, doc) = &sent[0];
    assert_eq!(
        to, ALICE_LAPTOP,
        "the setter, bob and the delegate are not told"
    );
    assert_eq!(doc["recipient"], ALICE_LAPTOP);
    assert!(doc["proof"].is_object(), "signed by the VTA: {doc}");
    let payload = doc["payload"].as_object().unwrap();
    assert_eq!(
        payload.len(),
        3,
        "the room, the member and the marker only: {doc}"
    );
    assert_eq!(payload["roomId"], ROOM);
    assert_eq!(payload["member"], f.alice.did.as_str());
    assert_eq!(payload["readMarker"], marker(415, Some(SEEN_AT)));
    assert!(
        !doc.to_string().contains(ALICE_PHONE),
        "never which client set it"
    );
    let schema = vti_specs::schema_index::schema_for(MOVED).expect("moved is pinned");
    trust_tasks_rs::validate::against_schema(schema, &doc["payload"]).expect("moved/0.1");
    // Item 5: sending it does not consume a watch.
    assert_eq!(
        f.state.room_key_watches.all().await.unwrap().len(),
        held_before
    );

    // A set that moves nothing sends nothing.
    set(&f, marker(400, None)).await;
    after_the_window().await;
    assert!(moved_pushes(&f).is_empty());
}

/// Producer item 3: a burst of sets within the window is one `moved`, carrying the marker in
/// force at its end; and a marker set by the laptop goes to the phone.
#[tokio::test]
async fn a_burst_is_coalesced_into_the_latest_marker() {
    let f = fixture().await;
    watching(&f, ALICE_PHONE, &f.alice.did, ROOM).await;
    watching(&f, ALICE_LAPTOP, &f.alice.did, ROOM).await;
    for v in [1, 2, 3, 4] {
        set(&f, marker(v, None)).await;
    }
    after_the_window().await;
    let sent = moved_pushes(&f);
    assert_eq!(sent.len(), 1, "one notice for the burst: {sent:?}");
    assert_eq!(sent[0].0, ALICE_LAPTOP);
    assert_eq!(sent[0].1["payload"]["readMarker"], marker(4, None));

    // The member marks it unread on the laptop: the phone takes the marker behind its own.
    set_as(
        &f,
        &client(ALICE_LAPTOP, "alice"),
        &f.alice.did,
        marker(0, None),
        true,
    )
    .await;
    after_the_window().await;
    let sent = moved_pushes(&f);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, ALICE_PHONE);
    assert_eq!(sent[0].1["payload"]["readMarker"], marker(0, None));
}

/// A client that may no longer act as the member is not told, though its watch is still held.
#[tokio::test]
async fn moved_is_checked_against_standing_when_sent() {
    let f = fixture().await;
    watching(&f, ALICE_LAPTOP, &f.alice.did, ROOM).await;
    vti_common::acl::delete_acl_entry(&f.state.acl_ks, ALICE_LAPTOP)
        .await
        .unwrap();
    set(&f, marker(3, None)).await;
    after_the_window().await;
    assert!(moved_pushes(&f).is_empty());
}

/// Item 7: kept with the member's group state, discarded with it, and never written beside
/// group state that is gone.
#[tokio::test]
async fn the_marker_goes_with_the_group_state() {
    let f = fixture().await;
    let member = Member::new(ROOM, &f.alice.did).unwrap();
    set(&f, marker(9, Some(SEEN_AT))).await;
    room_groups::record_removal_for_test(&f.state.room_groups_ks, &member, 2)
        .await
        .unwrap();
    assert!(
        room_groups::read_marker(&f.state.room_groups_ks, &member)
            .await
            .unwrap()
            .is_some(),
        "a removal keeps the group state, and the marker with it"
    );
    room_groups::forget(&f.state.room_groups_ks, &member)
        .await
        .unwrap();
    assert!(
        room_groups::read_marker(&f.state.room_groups_ks, &member)
            .await
            .unwrap()
            .is_none(),
        "discarded with the group state"
    );
    let out = set(&f, marker(10, None)).await;
    assert_eq!(code(&out), "rooms/keys/read-marker/set:notHeld", "{out}");
    // Bob's marker for the same room is his own, and untouched by alice's going.
    set_as(
        &f,
        &client(BOB_PHONE, "bob"),
        &f.bob.did,
        marker(1, None),
        false,
    )
    .await;
    room_groups::forget(&f.state.room_groups_ks, &member)
        .await
        .unwrap();
    let bobs = Member::new(ROOM, &f.bob.did).unwrap();
    assert!(
        room_groups::read_marker(&f.state.room_groups_ks, &bobs)
            .await
            .unwrap()
            .is_some()
    );
}

/// Item 9: a set writes no audit row — not its values, not that it happened, not when.
#[tokio::test]
async fn a_set_leaves_nothing_in_the_audit_trail() {
    let f = fixture().await;
    let before = f.state.audit_ks.prefix_iter_raw("").await.unwrap().len();
    set(&f, marker(31337, Some(SEEN_AT))).await;
    set(&f, marker(31338, None)).await;
    rewind(&f, marker(0, None)).await;
    let rows = f.state.audit_ks.prefix_iter_raw("").await.unwrap();
    for (_, v) in &rows {
        let text = String::from_utf8_lossy(v);
        assert!(!text.contains("31337") && !text.contains(SEEN_AT), "{text}");
        assert!(
            !text.contains("read-marker") && !text.contains("read_marker"),
            "{text}"
        );
    }
    assert_eq!(rows.len(), before, "no audit row for a set");
}

/// The spine keeps no read-marker response for redelivery and logs no receipt of a set.
#[test]
fn the_spine_keeps_and_logs_no_marker() {
    assert!(super::super::carries_personal_state(SET));
    assert!(super::super::carries_personal_state(&format!(
        "{SET}#request"
    )));
    assert!(super::super::carries_personal_state(LIST_0_3));
    assert!(!super::super::logs_receipt(SET));
    assert!(super::super::logs_receipt(LIST_0_3));
}

/// The marker lives in `room_groups`, which a backup carries (*Retention*: a MAY).
#[test]
fn the_marker_is_kept_in_the_room_groups_keyspace() {
    assert!(vta_keyspaces::BACKED_UP.contains(&vta_keyspaces::ROOM_GROUPS));
}

/// `ReadMarker`'s `Debug` never prints a value (item 9).
#[test]
fn a_marker_never_debug_prints_its_values() {
    let m = room_groups::ReadMarker::new(31337, Some(SEEN_AT.into())).unwrap();
    let printed = format!("{m:?}");
    assert!(
        !printed.contains("31337") && !printed.contains("2027"),
        "{printed}"
    );
}
