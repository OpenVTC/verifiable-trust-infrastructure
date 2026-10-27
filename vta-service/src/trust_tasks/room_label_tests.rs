//! `rooms/keys/label/0.1` and `rooms/keys/list/0.2` — one test per rule.

use super::*;
use crate::operations::persona::test_fixture::{self as personas, Persona};
use crate::operations::room_groups::Member;
use serde_json::json;
use trust_tasks_rs::TypeUri;

const ROOM: &str = "did:webvh:example.com:rooms:northwind";
const OTHER_ROOM: &str = "did:webvh:example.com:rooms:bookclub";
const LABEL: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_LABEL_0_1;
const LIST_0_2: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_LIST_0_2;

/// A detail's text no log, audit row or other task's output may ever carry.
const SECRET_NAME: &str = "Northwind tender — Dana's pricing room";

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

fn alice_caller() -> AuthClaims {
    crate::test_support::admin_claims_for_context("alice")
}

fn bob_caller() -> AuthClaims {
    crate::test_support::admin_claims_for_context("bob")
}

/// One VTA serving alice and bob, each with a persona in their own context; alice's persona
/// holds group state for [`ROOM`] and [`OTHER_ROOM`], bob's for [`ROOM`].
struct Fixture {
    state: AppState,
    _dir: tempfile::TempDir,
    alice: Persona,
    bob: Persona,
}

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
    Fixture {
        state,
        _dir: dir,
        alice,
        bob,
    }
}

async fn label(f: &Fixture, caller: &AuthClaims, payload: Value) -> Value {
    body(handle_label(&f.state, caller, request(LABEL, payload)).await)
}

async fn list(f: &Fixture, caller: &AuthClaims, payload: Value) -> Value {
    body(handle_list_v0_2(&f.state, caller, request(LIST_0_2, payload)).await)
}

/// The `rooms/keys/list/0.2` entry for `(room, member)`.
fn entry<'a>(listed: &'a Value, room: &str, member: &str) -> &'a Value {
    listed["payload"]["rooms"]
        .as_array()
        .unwrap_or_else(|| panic!("rooms: {listed}"))
        .iter()
        .find(|e| e["roomId"] == room && e["member"] == member)
        .unwrap_or_else(|| panic!("no entry for {room} as {member}: {listed}"))
}

/// The response conforms to the generated type the specification defines.
fn conforms_label(doc: &Value) -> label_spec::Response {
    serde_json::from_value(doc["payload"].clone()).unwrap_or_else(|e| panic!("{e}: {doc}"))
}

#[tokio::test]
async fn a_label_is_named_and_listed_back_only_when_asked() {
    let f = fixture().await;
    let out = label(
        &f,
        &alice_caller(),
        json!({
            "roomId": ROOM, "member": f.alice.did,
            "label": SECRET_NAME, "description": "Pricing.\nDana invited me.",
            "tags": ["work", "bids"],
        }),
    )
    .await;
    let typed = conforms_label(&out);
    assert!(typed.changed, "{out}");
    assert_eq!(out["payload"]["personal"]["label"], SECRET_NAME);
    assert_eq!(out["payload"]["personal"]["tags"], json!(["work", "bids"]));
    assert!(out["payload"]["personal"]["updatedAt"].is_string());

    // includePersonal: the label rides on its own entry and no other.
    let listed = list(&f, &alice_caller(), json!({ "includePersonal": true })).await;
    let _: list_spec::Response = serde_json::from_value(listed["payload"].clone()).unwrap();
    assert_eq!(
        entry(&listed, ROOM, &f.alice.did)["personal"]["label"],
        SECRET_NAME
    );
    assert!(entry(&listed, OTHER_ROOM, &f.alice.did)["personal"].is_null());

    // List 0.2 recipient item 2: absent or false, no entry carries one.
    for payload in [json!({}), json!({ "includePersonal": false })] {
        let listed = list(&f, &alice_caller(), payload).await;
        assert!(
            !listed.to_string().contains(SECRET_NAME),
            "a label without includePersonal: {listed}"
        );
        assert_eq!(entry(&listed, ROOM, &f.alice.did)["epoch"], 1);
    }
}

/// List 0.2 recipient item 1: one entry per room and member the caller may act as, each
/// naming its member — and no other.
#[tokio::test]
async fn list_0_2_names_each_member_and_only_the_callers() {
    let f = fixture().await;
    let everywhere = crate::test_support::super_admin_claims();
    let all = list(&f, &everywhere, json!({})).await;
    assert_eq!(
        all["payload"]["rooms"].as_array().unwrap().len(),
        3,
        "{all}"
    );
    entry(&all, ROOM, &f.alice.did);
    entry(&all, ROOM, &f.bob.did);

    let mine = list(&f, &bob_caller(), json!({ "includePersonal": true })).await;
    let rooms = mine["payload"]["rooms"].as_array().unwrap();
    assert_eq!(rooms.len(), 1, "{mine}");
    assert_eq!(rooms[0]["member"], f.bob.did);
    assert_eq!(
        mine["payload"]["ext"]["org.openvtc.rooms"]["held"][0]["context"], "bob",
        "the member's context rides beside it: {mine}"
    );
}

/// Recipient item 3: each detail given replaces, each removal removes, each absent detail
/// is unchanged.
#[tokio::test]
async fn details_are_patched_one_by_one() {
    let f = fixture().await;
    let base = json!({ "roomId": ROOM, "member": f.alice.did });
    let with = |extra: Value| {
        let mut p = base.clone();
        p.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        p
    };
    label(
        &f,
        &alice_caller(),
        with(json!({ "label": "Northwind", "description": "Pricing", "tags": ["work"] })),
    )
    .await;
    let out = label(
        &f,
        &alice_caller(),
        with(json!({ "notes": "Final numbers in March.", "removeDescription": true })),
    )
    .await;
    assert_eq!(
        out["payload"]["personal"],
        json!({
            "label": "Northwind", "notes": "Final numbers in March.", "tags": ["work"],
            "updatedAt": out["payload"]["personal"]["updatedAt"],
        }),
        "{out}"
    );
    // `tags` replaces the whole set.
    let out = label(&f, &alice_caller(), with(json!({ "tags": ["bids", "q3"] }))).await;
    assert_eq!(out["payload"]["personal"]["tags"], json!(["bids", "q3"]));
}

/// Items 5 and 6: nothing written, `changed: false` and `updatedAt` unmoved when nothing
/// would change — strings compared exactly, tags as a set.
#[tokio::test]
async fn a_repeat_changes_nothing_and_says_so() {
    let f = fixture().await;
    let set = json!({
        "roomId": ROOM, "member": f.alice.did, "label": "Northwind", "tags": ["a", "b"],
    });
    let first = label(&f, &alice_caller(), set.clone()).await;
    assert_eq!(first["payload"]["changed"], true);
    let at = first["payload"]["personal"]["updatedAt"].clone();

    let again = label(&f, &alice_caller(), set).await;
    assert_eq!(again["payload"]["changed"], false, "{again}");
    assert_eq!(again["payload"]["personal"]["updatedAt"], at);

    let reordered = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "tags": ["b", "a"] }),
    )
    .await;
    assert_eq!(reordered["payload"]["changed"], false, "a set: {reordered}");

    // Removing what is already absent is no change either.
    let absent = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "removeNotes": true }),
    )
    .await;
    assert_eq!(absent["payload"]["changed"], false, "{absent}");

    // Exact comparison: a case change is a change.
    let cased = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": "northwind" }),
    )
    .await;
    assert_eq!(cased["payload"]["changed"], true, "{cased}");
}

/// Item 7: what the member wrote is what they are shown — no trimming, folding or
/// normalisation.
#[tokio::test]
async fn details_are_kept_exactly_as_written() {
    let f = fixture().await;
    let name = "  Ångström Café\u{0301} ";
    let out = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": name, "tags": ["Work", "work"] }),
    )
    .await;
    assert_eq!(out["payload"]["personal"]["label"], name);
    assert_eq!(out["payload"]["personal"]["tags"], json!(["Work", "work"]));
}

/// Item 4: removing the last detail removes the label; the answer carries no `personal`.
#[tokio::test]
async fn removing_the_last_detail_removes_the_label() {
    let f = fixture().await;
    label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": "x", "tags": ["t"] }),
    )
    .await;
    let out = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "removeLabel": true, "removeTags": true }),
    )
    .await;
    conforms_label(&out);
    assert_eq!(out["payload"]["changed"], true);
    assert!(out["payload"].get("personal").is_none(), "{out}");
    let member = Member::new(ROOM, &f.alice.did).unwrap();
    assert!(
        room_groups::personal_label(&f.state.room_groups_ks, &member)
            .await
            .unwrap()
            .is_none(),
        "no empty label is stored"
    );
    let listed = list(&f, &alice_caller(), json!({ "includePersonal": true })).await;
    assert!(entry(&listed, ROOM, &f.alice.did).get("personal").is_none());

    let again = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "removeLabel": true }),
    )
    .await;
    assert_eq!(again["payload"]["changed"], false, "{again}");
}

/// Item 3: a request naming no change — only `ext` beside `roomId` and `member`, which the
/// schema's `minProperties` cannot tell from one — is `malformedRequest`.
#[tokio::test]
async fn an_ext_only_request_is_malformed() {
    let f = fixture().await;
    let out = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "ext": { "org.example": { "x": 1 } } }),
    )
    .await;
    assert_eq!(code(&out), "malformedRequest", "{out}");
}

/// The schema's own refusals, through the spine's validation: `minProperties`, a detail
/// both given and removed (`dependentSchemas`), `removeX: false`, a control character in
/// a one-line detail, an empty tag set.
#[tokio::test]
async fn the_schema_refuses_what_it_declares() {
    let schema = trust_tasks_rs::schema_index::schema_for(LABEL).expect("label is indexed");
    for bad in [
        json!({ "roomId": ROOM, "member": "did:key:z" }),
        json!({ "roomId": ROOM, "member": "did:key:z", "label": "x", "removeLabel": true }),
        json!({ "roomId": ROOM, "member": "did:key:z", "removeNotes": false }),
        json!({ "roomId": ROOM, "member": "did:key:z", "label": "one\ntwo" }),
        json!({ "roomId": ROOM, "member": "did:key:z", "tags": [] }),
        json!({ "roomId": ROOM, "label": "x" }),
    ] {
        assert!(
            trust_tasks_rs::validate::against_schema(schema, &bad).is_err(),
            "{bad}"
        );
    }
    let ok = json!({ "roomId": ROOM, "member": "did:key:z", "notes": "a\nb\tc" });
    trust_tasks_rs::validate::against_schema(schema, &ok).expect("line breaks in notes");
}

/// Item 2: no group state as this member, and a member the caller does not act as, are one
/// answer — the error does not say whether another persona holds the room.
#[tokio::test]
async fn not_held_is_one_answer_for_both_causes() {
    let f = fixture().await;
    // Bob's persona does hold ROOM, but alice's caller does not act as it.
    let not_mine = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.bob.did, "label": "x" }),
    )
    .await;
    // Bob's persona holds no group state for OTHER_ROOM.
    let not_held = label(
        &f,
        &bob_caller(),
        json!({ "roomId": OTHER_ROOM, "member": f.bob.did, "label": "x" }),
    )
    .await;
    // Nobody here holds this room at all, and the DID is nobody's.
    let nowhere = label(
        &f,
        &alice_caller(),
        json!({ "roomId": "did:web:nowhere", "member": "did:key:zNobody", "label": "x" }),
    )
    .await;
    for out in [&not_mine, &not_held, &nowhere] {
        assert_eq!(code(out), "rooms/keys/label:notHeld", "{out}");
    }
    let answer = |doc: &Value| {
        let mut p = doc["payload"].clone();
        p.as_object_mut().unwrap().remove("inResponseTo");
        p
    };
    assert_eq!(answer(&not_mine), answer(&not_held));
    assert_eq!(answer(&not_mine), answer(&nowhere));
    // And nothing was written for bob.
    let bobs = list(&f, &bob_caller(), json!({ "includePersonal": true })).await;
    assert!(entry(&bobs, ROOM, &f.bob.did).get("personal").is_none());
}

/// Recipient item 1 (and list 0.2 item 1): a delegate — an agent the member equipped —
/// is `permissionDenied` on `label` and acts as no member on `list`.
#[tokio::test]
async fn a_delegate_is_refused_and_lists_nothing() {
    let f = fixture().await;
    label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": SECRET_NAME }),
    )
    .await;
    let agent = "did:key:z6MkAgentOfAlice";
    let entry_: vti_common::acl::AclEntry = serde_json::from_value(json!({
        "did": agent, "role": "admin", "label": null,
        "allowed_contexts": ["alice"], "created_at": 0, "created_by": "test",
        "kind": { "kind": "service", "serviceKind": "ai-agent" },
    }))
    .unwrap();
    vti_common::acl::store_acl_entry(&f.state.acl_ks, &entry_)
        .await
        .unwrap();
    let auth = AuthClaims {
        did: agent.into(),
        ..alice_caller()
    };
    let out = label(
        &f,
        &auth,
        json!({ "roomId": ROOM, "member": f.alice.did, "label": "renamed" }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied", "{out}");
    let listed = list(&f, &auth, json!({ "includePersonal": true })).await;
    assert_eq!(listed["payload"]["rooms"], json!([]), "{listed}");
    assert!(!listed.to_string().contains(SECRET_NAME));
}

/// Item 8: the label stays when the member is removed from the room (the group state is
/// kept), and goes when the group state is discarded — with it, and only then.
#[tokio::test]
async fn a_label_outlives_removal_and_goes_with_the_group_state() {
    let f = fixture().await;
    let member = Member::new(ROOM, &f.alice.did).unwrap();
    label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": "Northwind" }),
    )
    .await;
    room_groups::record_removal_for_test(&f.state.room_groups_ks, &member, 2)
        .await
        .unwrap();
    let listed = list(&f, &alice_caller(), json!({ "includePersonal": true })).await;
    assert_eq!(
        entry(&listed, ROOM, &f.alice.did)["personal"]["label"],
        "Northwind",
        "kept on removal: {listed}"
    );

    room_groups::forget(&f.state.room_groups_ks, &member)
        .await
        .unwrap();
    assert!(
        room_groups::personal_label(&f.state.room_groups_ks, &member)
            .await
            .unwrap()
            .is_none(),
        "discarded with the group state"
    );
    // And a label cannot be written beside group state that is gone.
    let out = label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": "again" }),
    )
    .await;
    assert_eq!(code(&out), "rooms/keys/label:notHeld", "{out}");
    // Bob's label for the same room is his own, and untouched.
    let bob = Member::new(ROOM, &f.bob.did).unwrap();
    assert!(
        room_groups::personal_label(&f.state.room_groups_ks, &bob)
            .await
            .unwrap()
            .is_none()
    );
}

/// The label lives in `room_groups`, which a backup carries.
#[test]
fn the_label_is_kept_in_a_backed_up_keyspace() {
    assert!(vta_keyspaces::BACKED_UP.contains(&vta_keyspaces::ROOM_GROUPS));
}

/// Each persona keeps its own label for one room.
#[tokio::test]
async fn two_personas_keep_two_labels_for_one_room() {
    let f = fixture().await;
    label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": "Alice's name" }),
    )
    .await;
    label(
        &f,
        &bob_caller(),
        json!({ "roomId": ROOM, "member": f.bob.did, "label": "Bob's name" }),
    )
    .await;
    let everywhere = crate::test_support::super_admin_claims();
    let listed = list(&f, &everywhere, json!({ "includePersonal": true })).await;
    assert_eq!(
        entry(&listed, ROOM, &f.alice.did)["personal"]["label"],
        "Alice's name"
    );
    assert_eq!(
        entry(&listed, ROOM, &f.bob.did)["personal"]["label"],
        "Bob's name"
    );
}

/// Item 10: the audit row says a label was written, for which room and member and whether
/// it changed — never what it says.
#[tokio::test]
async fn the_audit_trail_never_carries_a_labels_text() {
    let f = fixture().await;
    label(
        &f,
        &alice_caller(),
        json!({
            "roomId": ROOM, "member": f.alice.did, "label": SECRET_NAME,
            "notes": SECRET_NAME, "tags": ["secret-tag-text"],
        }),
    )
    .await;
    let rows = f
        .state
        .audit_ks
        .prefix_iter_raw("")
        .await
        .expect("scan the audit log");
    let mut saw_row = false;
    for (_, v) in rows {
        let text = String::from_utf8_lossy(&v);
        assert!(
            !text.contains(SECRET_NAME),
            "audit row carries the label: {text}"
        );
        assert!(
            !text.contains("secret-tag-text"),
            "audit row carries a tag: {text}"
        );
        saw_row |= text.contains("rooms.keys.label");
    }
    assert!(saw_row, "the write is audited");
}

/// Item 9: nothing that completes, signs or seals for the member reads a label. At run
/// time — a seal and an open with a label stored carry none of it — and in the source: the
/// one reader, [`room_groups::personal_label`], is called from this module alone, so no
/// `act`, `seal` or `present` path can put it in what it produces.
#[tokio::test]
async fn a_label_never_reaches_what_the_vta_seals_or_opens() {
    let f = fixture().await;
    label(
        &f,
        &alice_caller(),
        json!({ "roomId": ROOM, "member": f.alice.did, "label": SECRET_NAME }),
    )
    .await;
    let named = json!({ "org.openvtc.rooms": { "member": f.alice.did } });
    let sealed = body(
        crate::trust_tasks::room_act::handle_seal_v0_2(
            &f.state,
            &alice_caller(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_SEAL_0_2,
                json!({
                    "roomId": ROOM, "key": "notes/1", "version": 1,
                    "plaintext": "aGVsbG8", "ext": named,
                }),
            ),
        )
        .await,
    );
    assert!(sealed["payload"]["sealed"].is_object(), "{sealed}");
    assert!(!sealed.to_string().contains(SECRET_NAME), "{sealed}");
    let opened = body(
        crate::trust_tasks::room_group::handle_open_v0_2(
            &f.state,
            &alice_caller(),
            request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_2,
                json!({
                    "roomId": ROOM, "key": "notes/1", "version": 1,
                    "sealed": sealed["payload"]["sealed"], "ext": named,
                }),
            ),
        )
        .await,
    );
    assert_eq!(opened["payload"]["plaintext"], "aGVsbG8", "{opened}");
    assert!(!opened.to_string().contains(SECRET_NAME));
}

#[test]
fn only_the_label_and_list_tasks_read_a_label() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut readers = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs")
                && std::fs::read_to_string(&p)
                    .unwrap()
                    .contains("personal_label(")
            {
                readers.push(p.strip_prefix(&src).unwrap().display().to_string());
            }
        }
    }
    readers.sort();
    assert_eq!(
        readers,
        vec![
            "operations/room_groups.rs",
            "trust_tasks/room_label.rs",
            "trust_tasks/room_label_tests.rs",
        ],
        "a new reader of the personal label: it must never reach act, seal or present \
         (rooms/keys/label/0.1 recipient item 9)"
    );
}

/// *No optimistic concurrency*, and none needed: two writes racing on different details
/// both land, because each is applied to the label as it then stands.
#[tokio::test]
async fn racing_writes_to_different_details_both_land() {
    let f = fixture().await;
    let member = Member::new(ROOM, &f.alice.did).unwrap();
    let ks = &f.state.room_groups_ks;
    let rename = room_groups::LabelChange {
        label: room_groups::LabelDetail::Set("from the phone".into()),
        ..Default::default()
    };
    let notes = room_groups::LabelChange {
        notes: room_groups::LabelDetail::Set("from the laptop".into()),
        ..Default::default()
    };
    let now = chrono::Utc::now();
    let (a, b) = tokio::join!(
        room_groups::set_label(ks, &member, &rename, now),
        room_groups::set_label(ks, &member, &notes, now),
    );
    a.unwrap();
    b.unwrap();
    let stored = room_groups::personal_label(ks, &member)
        .await
        .unwrap()
        .expect("a label");
    assert_eq!(stored.label.as_deref(), Some("from the phone"));
    assert_eq!(stored.notes.as_deref(), Some("from the laptop"));
}
