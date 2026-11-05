//! `rooms/keys/watch/0.1`, `rooms/keys/changed/0.1` and `rooms/keys/act/0.12` end to end
//! against a **real** room host (the fixtures of `room_profile_tests`): the VTA arms
//! `rooms/watch` at the host as the member, the host's own watch fires on a put, its
//! `rooms/changed` reaches the VTA at the watch's address (here handed over in-process
//! where a mediator would carry it), and the VTA passes one `rooms/keys/changed` on to the
//! caller and forgets the watch.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::trust_tasks::room_key_watch::{handle_watch, receive_signal, sweep};

const WATCH: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WATCH_0_1;
const CHANGED: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_CHANGED_0_1;
const MEDIATOR: &str = "did:example:mediator";

/// The host's outbound leg, handed straight to the member's VTA as the address's
/// connection would: the transport has proved the host as the sender.
struct ToVta {
    state: AppState,
    host_did: String,
}

#[async_trait::async_trait]
impl vti_rooms::watch::Signals for ToVta {
    async fn reachable(&self, _address: &str) -> bool {
        true
    }
    async fn send_changed(&self, address: &str, payload: Value) -> Result<(), String> {
        let doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": vti_rooms::watch::CHANGED_TYPE,
            "issuer": self.host_did,
            "recipient": address,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        });
        receive_signal(
            &self.state,
            address,
            &self.host_did,
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await;
        Ok(())
    }
}

/// An open room on a real host whose watches signal `member`'s VTA, which has a mediator to
/// receive at and an ACL entry for its caller.
async fn watched_open_room() -> (Host, Party, Vta) {
    let host = start_host().await;
    let (room, member) = open_room_on(&host).await;
    receive_at_mediator(&member).await;
    host.state.set_signals(Arc::new(ToVta {
        state: member.state.clone(),
        host_did: host.did.clone(),
    }));
    host.state.set_watch_signal_delay_ms(10, 20);
    (host, room, member)
}

/// Give `v` a mediator (so it can mint addresses and push to its caller) and an ACL entry
/// for the test administrator (so the sweep finds the caller standing).
async fn receive_at_mediator(v: &Vta) {
    use crate::messaging::registry::MediatorBinding;
    v.state
        .mediator_registry
        .record_activate(MediatorBinding {
            mediator_did: MEDIATOR.into(),
            endpoint: "https://mediator.test".into(),
        })
        .await;
    v.state.config.write().await.messaging = Some(vti_common::config::MessagingConfig {
        mediator_url: String::new(),
        mediator_did: MEDIATOR.into(),
        mediator_host: None,
        setup_acl: false,
        drain_inbox_on_start: false,
    });
    let caller = admin().did;
    if vti_common::acl::get_acl_entry(&v.state.acl_ks, &caller)
        .await
        .unwrap()
        .is_none()
    {
        let entry = vti_common::acl::AclEntry::new(caller, crate::acl::Role::Admin, "test");
        crate::acl::store_acl_entry(&v.state.acl_ks, &entry)
            .await
            .unwrap();
    }
}

async fn watch(v: &Vta, payload: Value) -> Value {
    body(handle_watch(&v.state, &admin(), request(WATCH, payload)).await)
}

fn arm(v: &Vta, host: &Host, rooms: &[&str]) -> Value {
    let rooms: Vec<Value> = rooms
        .iter()
        .map(|r| json!({ "roomId": r, "sinceVersion": 0 }))
        .collect();
    json!({ "member": v.persona, "host": host.did, "rooms": rooms })
}

fn code(doc: &Value) -> &str {
    doc["payload"]["code"].as_str().unwrap_or_default()
}

/// The pass-ons the VTA queued for its caller so far.
fn passed_on(v: &Vta) -> Vec<Value> {
    crate::messaging::push::take_pushes(&v.state)
        .into_iter()
        .filter(|p| p.body["type"] == CHANGED)
        .map(|p| {
            assert_eq!(
                p.recipient_did,
                admin().did,
                "only to the caller that armed it"
            );
            p.body
        })
        .collect()
}

/// Wait for the host's delayed signal to reach the VTA and be passed on.
async fn wait_for_pass_on(v: &Vta) -> Vec<Value> {
    let mut seen = Vec::new();
    for _ in 0..200 {
        seen.extend(passed_on(v));
        if !seen.is_empty() {
            // A second signal for the same arming would arrive within the same delay.
            tokio::time::sleep(Duration::from_millis(100)).await;
            seen.extend(passed_on(v));
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    seen
}

async fn held(v: &Vta) -> Vec<crate::operations::room_key_watch::WatchRecord> {
    v.state.room_key_watches.all().await.unwrap()
}

/// Item 3, 5, 8 and `rooms/keys/changed` Producer items 1–2: the VTA arms the host's watch
/// as the member at an address of its own, the host's one signal for a put is passed on
/// once to the caller — the room, member, host and latest version, nothing else — and the
/// watch is forgotten, so a later signal at that address is dropped.
#[tokio::test]
async fn a_watch_through_the_vta_passes_one_signal_on_and_is_forgotten() {
    let (host, room, member) = watched_open_room().await;
    let answer = watch(&member, arm(&member, &host, &[&room.did])).await;
    let outcome = &answer["payload"]["watches"][0];
    assert_eq!(outcome["armed"], true, "{answer}");
    assert!(outcome["expiresAt"].is_string(), "{answer}");
    assert_eq!(answer["payload"]["member"], member.persona.as_str());
    assert_eq!(host.received(vti_rooms::watch::WATCH_TYPE), 1);

    let records = held(&member).await;
    assert_eq!(records.len(), 1);
    let address = records[0].address.clone();
    let vta_did = member.state.config.read().await.vta_did.clone().unwrap();
    assert!(address.starts_with("did:peer:2"), "{address}");
    for not in [&vta_did, &member.persona, &admin().did] {
        assert_ne!(
            &address, not,
            "item 5: never the VTA's, member's or caller's DID"
        );
    }
    assert!(
        !answer.to_string().contains(&address),
        "the caller never learns the address"
    );

    put_open_v0_5(&member, &room.did, &host, "n1", json!({ "body": "hello" })).await;
    let sent = wait_for_pass_on(&member).await;
    assert_eq!(sent.len(), 1, "one signal per arming: {sent:?}");
    let doc = &sent[0];
    assert_eq!(doc["issuer"], vta_did.as_str());
    assert!(doc["proof"].is_object(), "signed by the VTA: {doc}");
    let payload = doc["payload"].as_object().unwrap();
    assert_eq!(payload.len(), 4, "nothing but the four members: {doc}");
    assert_eq!(payload["roomId"], room.did.as_str());
    assert_eq!(payload["member"], member.persona.as_str());
    assert_eq!(payload["host"], host.did.as_str());
    assert!(payload["latestVersion"].as_u64().unwrap() >= 1);
    assert!(!doc.to_string().contains(&address), "never the address");
    assert!(
        vti_specs::schema_index::schema_for(CHANGED).is_some_and(|s| {
            trust_tasks_rs::validate::against_schema(s, &doc["payload"]).is_ok()
        }),
        "the pass-on validates against rooms/keys/changed/0.1"
    );
    assert!(
        held(&member).await.is_empty(),
        "the fired watch is forgotten"
    );

    // A late or replayed signal at the forgotten address is dropped.
    let replay = json!({
        "type": vti_rooms::watch::CHANGED_TYPE, "issuer": host.did, "recipient": address,
        "payload": { "roomId": room.did, "latestVersion": 9 },
    });
    receive_signal(
        &member.state,
        &address,
        &host.did,
        &serde_json::to_vec(&replay).unwrap(),
    )
    .await;
    put_open_v0_5(&member, &room.did, &host, "n2", json!({ "body": "again" })).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        passed_on(&member).is_empty(),
        "nothing after the one signal"
    );
}

/// Item 5: a re-arm of a watch that has not fired keeps its address (the host's watch is
/// replaced, not added to); after a signal the next arming takes a new one.
#[tokio::test]
async fn re_arming_keeps_the_address_until_the_watch_fires() {
    let (host, room, member) = watched_open_room().await;
    let first = watch(&member, arm(&member, &host, &[&room.did])).await;
    assert_eq!(first["payload"]["watches"][0]["armed"], true, "{first}");
    let address = held(&member).await[0].address.clone();
    let again = watch(&member, arm(&member, &host, &[&room.did])).await;
    assert_eq!(again["payload"]["watches"][0]["armed"], true, "{again}");
    let records = held(&member).await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].address, address,
        "an unfired watch keeps its address"
    );

    put_open_v0_5(&member, &room.did, &host, "n1", json!({ "body": "hello" })).await;
    assert_eq!(wait_for_pass_on(&member).await.len(), 1);
    let version = 1;
    let rearmed = watch(
        &member,
        json!({ "member": member.persona, "host": host.did,
                "rooms": [{ "roomId": room.did, "sinceVersion": version }] }),
    )
    .await;
    assert_eq!(rearmed["payload"]["watches"][0]["armed"], true, "{rearmed}");
    let records = held(&member).await;
    assert_eq!(records.len(), 1);
    assert_ne!(records[0].address, address, "after a signal, a new address");
}

/// A cancel ends the watch at the host and here; one the VTA does not hold answers
/// `armed: false` without asking the host.
#[tokio::test]
async fn a_cancel_ends_the_watch_and_a_cancel_of_none_asks_nobody() {
    let (host, room, member) = watched_open_room().await;
    watch(&member, arm(&member, &host, &[&room.did])).await;
    assert_eq!(held(&member).await.len(), 1);
    let cancel = json!({ "member": member.persona, "host": host.did,
                         "rooms": [{ "roomId": room.did }], "cancel": true });
    let out = watch(&member, cancel.clone()).await;
    assert_eq!(out["payload"]["watches"][0]["armed"], false, "{out}");
    assert!(
        out["payload"]["watches"][0].get("refused").is_none(),
        "{out}"
    );
    assert!(held(&member).await.is_empty());
    assert_eq!(
        host.received(vti_rooms::watch::WATCH_TYPE),
        2,
        "armed, then cancelled"
    );

    let again = watch(&member, cancel).await;
    assert_eq!(again["payload"]["watches"][0]["armed"], false, "{again}");
    assert_eq!(
        host.received(vti_rooms::watch::WATCH_TYPE),
        2,
        "a cancel of a watch not held is answered here"
    );

    // Nothing fires for a cancelled watch.
    put_open_v0_5(&member, &room.did, &host, "n1", json!({ "body": "hello" })).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(passed_on(&member).is_empty());
}

/// This VTA's own bound is the room's `limitReached`, and nothing is asked of the host; a
/// VTA with no mediator receives at no address and holds no watch at all.
#[tokio::test]
async fn past_the_vtas_own_bound_a_room_is_limit_reached() {
    use crate::operations::room_key_watch::{MAX_PER_MEMBER, RoomKeyWatches};
    let (host, room, member) = watched_open_room().await;
    {
        let _g = member.state.room_key_watches.lock().await;
        for i in 0..MAX_PER_MEMBER {
            let r = RoomKeyWatches::new_record(
                &admin().did,
                &member.persona,
                &format!("did:example:room-{i}"),
                &host.did,
                MEDIATOR,
                Utc::now().timestamp() + 3600,
            )
            .unwrap();
            member.state.room_key_watches.put(&r).await.unwrap();
        }
    }
    let out = watch(&member, arm(&member, &host, &[&room.did])).await;
    assert_eq!(
        out["payload"]["watches"][0]["refused"], "limitReached",
        "{out}"
    );
    assert_eq!(out["payload"]["watches"][0]["armed"], false);
    assert_eq!(host.received(vti_rooms::watch::WATCH_TYPE), 0);

    let (host2, room2, bare) = {
        let host = start_host().await;
        let (room, v) = open_room_on(&host).await;
        (host, room, v)
    };
    let out = watch(&bare, arm(&bare, &host2, &[&room2.did])).await;
    assert_eq!(
        out["payload"]["watches"][0]["refused"], "limitReached",
        "{out}"
    );
    assert_eq!(host2.received(vti_rooms::watch::WATCH_TYPE), 0);
}

/// Item 2: a member this VTA holds no keys for that the caller may act as is refused whole,
/// `memberNotPrincipal` naming it; a room named twice is malformed; a room whose credentials
/// are not held is that room's `notAMember`, beside the others.
#[tokio::test]
async fn the_request_and_each_room_are_refused_for_what_they_are() {
    let (host, room, member) = watched_open_room().await;
    let stranger = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    let out = watch(
        &member,
        json!({ "member": stranger, "host": host.did, "rooms": [{ "roomId": room.did }] }),
    )
    .await;
    assert_eq!(code(&out), "rooms/keys/watch:memberNotPrincipal", "{out}");
    assert_eq!(out["payload"]["details"]["member"], stranger);
    assert_eq!(host.received(vti_rooms::watch::WATCH_TYPE), 0);

    let twice = watch(&member, arm(&member, &host, &[&room.did, &room.did])).await;
    assert_eq!(code(&twice), "malformedRequest", "{twice}");

    let elsewhere = Party::new();
    let out = watch(&member, arm(&member, &host, &[&elsewhere.did, &room.did])).await;
    let w = &out["payload"]["watches"];
    assert_eq!(
        w[0]["roomId"],
        elsewhere.did.as_str(),
        "in the order asked: {out}"
    );
    assert_eq!(w[0]["refused"], "notAMember", "{out}");
    assert_eq!(w[1]["armed"], true, "{out}");
}

/// A signal is passed on only from the watch's host and for its room: another sender, or
/// another room, at the address is dropped and the watch stays armed.
#[tokio::test]
async fn a_signal_from_anyone_but_the_host_or_for_another_room_is_dropped() {
    let (host, room, member) = watched_open_room().await;
    watch(&member, arm(&member, &host, &[&room.did])).await;
    let address = held(&member).await[0].address.clone();
    let signal = |issuer: &str, room_id: &str| {
        serde_json::to_vec(&json!({
            "type": vti_rooms::watch::CHANGED_TYPE, "issuer": issuer, "recipient": address,
            "payload": { "roomId": room_id, "latestVersion": 4 },
        }))
        .unwrap()
    };
    let other = Party::new();
    receive_signal(
        &member.state,
        &address,
        &other.did,
        &signal(&other.did, &room.did),
    )
    .await;
    receive_signal(
        &member.state,
        &address,
        &host.did,
        &signal(&host.did, &other.did),
    )
    .await;
    assert!(passed_on(&member).is_empty());
    assert_eq!(held(&member).await.len(), 1, "still armed");
    receive_signal(
        &member.state,
        &address,
        &host.did,
        &signal(&host.did, &room.did),
    )
    .await;
    assert_eq!(passed_on(&member).len(), 1);
    assert!(held(&member).await.is_empty());
}

/// Item 7: a watch is forgotten when it lapses and when its caller may no longer act as the
/// member.
#[tokio::test]
async fn the_sweep_forgets_lapsed_watches_and_those_whose_caller_lost_standing() {
    let (host, room, member) = watched_open_room().await;
    watch(&member, arm(&member, &host, &[&room.did])).await;
    assert_eq!(
        sweep(&member.state).await.unwrap(),
        0,
        "a standing watch stays"
    );
    assert_eq!(held(&member).await.len(), 1);

    let mut lapsed = held(&member).await.remove(0);
    lapsed.expires_at = Utc::now().timestamp() - 1;
    {
        let _g = member.state.room_key_watches.lock().await;
        member.state.room_key_watches.put(&lapsed).await.unwrap();
    }
    assert_eq!(sweep(&member.state).await.unwrap(), 1);
    assert!(held(&member).await.is_empty());

    watch(&member, arm(&member, &host, &[&room.did])).await;
    assert_eq!(held(&member).await.len(), 1);
    vti_common::acl::delete_acl_entry(&member.state.acl_ks, &admin().did)
        .await
        .unwrap();
    assert_eq!(
        sweep(&member.state).await.unwrap(),
        1,
        "the caller lost standing"
    );
    assert!(held(&member).await.is_empty());
}

/// `rooms/keys/act/0.12` adds `rooms/watch/0.1` (`read`, presentation inserted), which 0.11
/// refuses; Producer item 6 — the address is never the caller's identifier, this VTA's DID
/// or the member's — is refused here as malformed before anything is signed.
#[tokio::test]
async fn act_0_12_completes_a_watch_and_refuses_an_address_item_6_forbids() {
    let (host, room, member) = watched_open_room().await;
    let vta_did = member.state.config.read().await.vta_did.clone().unwrap();
    let act = |address: &str, uri: &'static str| {
        let state = member.state.clone();
        let document = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": vti_rooms::watch::WATCH_TYPE,
            "recipient": host.did,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "roomId": room.did, "address": address },
        });
        async move {
            let doc = request(uri, json!({ "document": document }));
            body(if uri == vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_12 {
                crate::trust_tasks::room_act::handle_act_v0_12(&state, &admin(), doc).await
            } else {
                crate::trust_tasks::room_act::handle_act_v0_11(&state, &admin(), doc).await
            })
        }
    };
    let own = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    #[allow(deprecated)]
    let v0_11 = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_11;
    let v0_12 = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_12;
    assert_eq!(
        code(&act(own, v0_11).await),
        "rooms/keys/act:typeNotActable",
        "0.11's table does not list rooms/watch"
    );
    for forbidden in [admin().did, vta_did.clone(), member.persona.clone()] {
        let out = act(&forbidden, v0_12).await;
        assert_eq!(code(&out), "malformedRequest", "{forbidden}: {out}");
        assert!(out.to_string().contains("Producer"), "{out}");
    }
    let out = act(own, v0_12).await;
    let completed = &out["payload"]["document"];
    assert_eq!(completed["issuer"], member.persona.as_str(), "{out}");
    assert_eq!(
        completed["payload"]["address"], own,
        "the address is unaltered"
    );
    assert!(completed["payload"]["presentation"].is_object(), "{out}");
    let answer = room_host::dispatch(&host.state, &serde_json::to_vec(completed).unwrap()).await;
    assert_eq!(
        answer.document["payload"]["armed"], true,
        "{}",
        answer.document
    );
}
