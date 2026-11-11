//! `rooms/keys/watch/0.1` and `rooms/keys/changed/0.1` through a **real mediator**.
//!
//! ## Why this exists
//!
//! `vta-service`'s `room_key_watch_tests` run the VTA's half of a room watch against a real
//! room host, but hand the host's `rooms/changed` to the VTA in-process, where a mediator
//! would carry it. So three things the flow rests on were unproven:
//!
//! 1. the mediator accepts a session for a `did:peer:2` watch address the VTA minted a
//!    moment ago, which nobody registered there;
//! 2. it routes the host's `rooms/changed` to that address — including one sent before the
//!    address's connection opened, which it must hold until then;
//! 3. it carries the VTA's `rooms/keys/changed` on to the wallet that asked for the watch.
//!
//! ## The parties
//!
//! One embedded mediator, open (`explicit_deny`) and granting a DID it has never seen the
//! least a DIDComm receiver needs ([`GLOBAL_ACL`]) — not the fixture's default, which grants
//! an unregistered DID no `LOCAL` and so would refuse every watch address, and not
//! `acl::allow_all()`, which would hide what an address actually depends on. The VTA, the
//! host and the wallet are accounts their operators provisioned; the watch address is not.
//! On it: a VTA running its production inbound loop and its address supervisor
//! (`messaging::watch_addresses`), a room host serving over the mediator
//! (`room_host::didcomm::serve`) and over HTTPS, and a wallet with a TSP session of its own.
//! The wallet asks the VTA over TSP; the VTA arms the host over HTTPS (the only binding that
//! can carry a document its member issued); the host signals the address over DIDComm
//! through the mediator; the VTA pushes the pass-on to the wallet through the mediator.
//!
//! The room's records are written by handing the member-completed `rooms/records/put/0.5`
//! to the host in-process: the write is only the trigger, and how a write reaches a host is
//! covered elsewhere.
//!
//! Hermetic: no network, no deployed service, so these run in CI unignored.

use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_test_mediator::MediatorACLSet;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::TspSession;
use vta_sdk::trust_tasks::{
    TASK_ROOMS_KEYS_ACT_0_12, TASK_ROOMS_KEYS_CHANGED_0_1, TASK_ROOMS_KEYS_WATCH_0_1,
};
use vta_service::test_support::{MockVta, seed_holder_key, seed_room_membership};
use vti_rooms_dtg::test_support::Party;

mod common;

/// What the mediator grants a DID it has never seen (`global_acl_default`). A watch address
/// is such a DID, and nothing registers it or widens its account, so this is all it gets:
/// the least an open (`explicit_deny`) mediator must grant for a self-registered DID to
/// connect and receive DIDComm — an open access list, `LOCAL`, and `RECEIVE_FORWARDED`,
/// because every DIDComm message through a mediator arrives as a forward.
///
/// Not the shipped `mediator.toml` default (`DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES`).
/// Under that one a self-registered DID connects but receives nothing: `DENY_ALL` makes its
/// access list an empty allowlist and grants no `RECEIVE_FORWARDED`, and no self-change bit
/// lets it widen either. Run against it, this test arms the watch and opens the address's
/// connection, and the mediator then refuses the host's signal (`e.p.delivery.refused`).
const GLOBAL_ACL: &str =
    "MODE_EXPLICIT_DENY,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,RECEIVE_FORWARDED";

/// The member's persona key, under the VTA's seed.
const MEMBER_KEY_PATH: &str = "m/44'/0'/7'/0'/3'";

/// How long a request to the VTA may take to be answered.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the pass-on may take to reach the wallet once the record is written. The host
/// waits 10–20 ms before signalling here (`set_watch_signal_delay_ms`); the rest is two hops
/// through the mediator and the VTA's push.
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(20);

/// How long to listen for a second signal that must not come. Far longer than the host's
/// delay plus both hops took for the first.
const QUIET_PERIOD: Duration = Duration::from_secs(5);

/// Deterministic `did:key` + multibase private key from a seed byte — the same helper as
/// the other TSP binaries in this crate.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

/// Everything one run needs, torn down by [`World::shutdown`].
struct World {
    mock: MockVta,
    host: Arc<room_host::HostState>,
    host_did: String,
    host_task: tokio::task::JoinHandle<()>,
    http_task: tokio::task::JoinHandle<()>,
    _host_dir: tempfile::TempDir,
    room: String,
    member: String,
    wallet: TspSession,
    wallet_did: String,
    wallet_key: String,
}

impl World {
    /// The VTA, its mediator, a room host on that mediator, an open room the VTA holds a
    /// member's persona for, and a wallet connected and related to the VTA. With
    /// `supervise`, the VTA's address supervisor runs from the start, as it does at boot.
    async fn start(wallet_seed: u8, supervise: bool) -> Self {
        common::init_tracing();

        let mut mock = MockVta::start_with_transports_using(|b| {
            b.global_acl_default(
                MediatorACLSet::from_string_ruleset(GLOBAL_ACL).expect("the global ACL parses"),
            )
        })
        .await;
        mock.configure_messaging().await;
        if supervise {
            mock.start_watch_addresses();
        }
        let mediator = mock.mediator_did().to_string();

        // The host: reachable at the mediator over DIDComm, which is where it signals from,
        // and over the Trust-Task HTTPS binding, which is how the VTA reaches it. The VTA
        // sends a host only documents its *member* issued, and DIDComm and TSP would
        // authenticate the VTA as the sender instead (the binding's `identityMismatch`), so
        // a host the VTA arms watches at advertises an HTTPS endpoint. One embedded mediator
        // DID keeps the `did:peer:2` under the 1000-byte resolver limit.
        let host_dir = tempfile::tempdir().expect("host data dir");
        let host = room_host::open_state(host_dir.path()).expect("a room host");
        host.set_room_creation(room_host::creation::RoomCreation::any_creator());
        host.set_watch_signal_delay_ms(10, 20);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the host's HTTP port");
        let host_url = format!("http://{}", listener.local_addr().unwrap());
        let http_task = tokio::spawn({
            let router = room_host::router(host.clone());
            async move {
                let _ = axum::serve(listener, router).await;
            }
        });
        let mut services = vta_service::operations::did_peer::mediator_did_didcomm_service(
            &mediator,
            vec!["didcomm/v2".into()],
            vec![],
        );
        services.push(affinidi_tdk::dids::PeerService {
            type_: "TrustTaskHTTPS".into(),
            endpoint: affinidi_tdk::dids::PeerServiceEndpoint::Long(
                affinidi_tdk::dids::OneOrMany::One(affinidi_tdk::dids::PeerServiceEndpointLong {
                    uri: host_url,
                    accept: vec![],
                    routing_keys: vec![],
                }),
            ),
            id: None,
        });
        let (host_did, host_secrets) =
            vta_service::operations::did_peer::mint_did_peer_with_services(services)
                .expect("mint the host's identity");
        assert!(host_did.len() < 1000, "host DID too long to resolve");
        // A service's account, provisioned by its operator as the VTA's is: the shipped
        // default grants a self-registered DID no `SEND_FORWARDED`, and every DIDComm send
        // through the mediator is a forward. The watch address gets no such help.
        mock.register_mediator_account(&host_did).await;
        let host_task = tokio::spawn({
            let host = host.clone();
            let identity =
                room_host::didcomm::HostIdentity::from_vta(host_did.clone(), host_secrets);
            let mediator = mediator.clone();
            async move {
                if let Err(e) = room_host::didcomm::serve(host, identity, mediator).await {
                    panic!("the room host stopped serving: {e}");
                }
            }
        });

        // The room, and the member the VTA holds for it.
        let room = Party::new();
        let member = seed_holder_key(&mock.ctx.state, MEMBER_KEY_PATH, None).await;
        seed_room_membership(
            &mock.ctx.state,
            &room.did,
            &room.secret,
            &member,
            &["read", "write"],
        )
        .await;
        vti_rooms::storage::create_room(
            host.rooms(),
            &vti_rooms::Room {
                room_id: room.did.clone(),
                owner_did: member.clone(),
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
                signal_delay: Default::default(),
                epoch_floor: None,
                frozen_at: None,
            },
        )
        .await
        .expect("seed the room at the host");

        // The wallet: the VTA's client, with a mediator session of its own.
        let (wallet_did, wallet_key) = did_key_from_seed(wallet_seed);
        mock.register_mediator_account(&wallet_did).await;
        mock.grant_super_admin(&wallet_did).await;
        let wallet = TspSession::connect(&wallet_did, &wallet_key, &mediator)
            .await
            .expect("the wallet's TSP session connects");
        wallet
            .relate(mock.vta_did())
            .await
            .expect("the wallet relates to the VTA");

        Self {
            mock,
            host,
            host_did,
            host_task,
            http_task,
            _host_dir: host_dir,
            room: room.did,
            member,
            wallet,
            wallet_did,
            wallet_key,
        }
    }

    /// Send `payload` as `type_uri` to the VTA over the wallet's session, signed by the
    /// wallet, and return the answer's document.
    async fn ask(&self, type_uri: &str, payload: Value) -> Value {
        let mut doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
            "issuer": self.wallet_did,
            "recipient": self.mock.vta_did(),
            "payload": payload,
        }))
        .expect("a well-formed Trust Task");
        vta_sdk::trust_task_sign::sign_in_place(&mut doc, &self.wallet_did, &self.wallet_key)
            .await
            .expect("the wallet signs its request");
        let reply = self
            .wallet
            .request(
                self.mock.vta_did(),
                self.mock.mediator_did(),
                &serde_json::to_vec(&doc).unwrap(),
                REPLY_TIMEOUT,
            )
            .await
            .unwrap_or_else(|e| panic!("the VTA did not answer {type_uri}: {e}"));
        let value: Value = serde_json::from_str(&reply).expect("the answer is JSON");
        let doc = value.get("document").cloned().unwrap_or(value);
        assert_eq!(
            doc["type"],
            format!("{type_uri}#response"),
            "the VTA refused {type_uri}: {doc:#}"
        );
        doc
    }

    /// Arm a watch on the room at the host, and return the address the VTA minted for it.
    async fn arm(&self) -> String {
        let answer = self
            .ask(
                TASK_ROOMS_KEYS_WATCH_0_1,
                json!({
                    "member": self.member,
                    "host": self.host_did,
                    "rooms": [{ "roomId": self.room, "sinceVersion": 0 }],
                }),
            )
            .await;
        let outcome = &answer["payload"]["watches"][0];
        assert_eq!(
            outcome["armed"], true,
            "the VTA could not arm the watch at the host over the mediator: {answer:#}"
        );
        let held = self
            .mock
            .ctx
            .state
            .room_key_watches
            .all()
            .await
            .expect("read the VTA's watches");
        assert_eq!(held.len(), 1, "one watch held: {held:?}");
        let address = held[0].address.clone();
        assert!(address.starts_with("did:peer:2"), "{address}");
        address
    }

    /// Write a record to the room as the member — completed by the VTA with
    /// `rooms/keys/act/0.12`, handed to the host — and return the version it took.
    async fn write(&self, key: &str) -> u64 {
        let unsigned = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE,
            "recipient": self.host_did,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "roomId": self.room, "key": key, "cleartext": { "body": key } },
        });
        let acted = self
            .ask(TASK_ROOMS_KEYS_ACT_0_12, json!({ "document": unsigned }))
            .await;
        let completed = &acted["payload"]["document"];
        assert!(completed.is_object(), "{acted:#}");
        let answer = room_host::dispatch(&self.host, &serde_json::to_vec(completed).unwrap()).await;
        let doc = answer.document;
        assert!(
            doc["type"]
                .as_str()
                .is_some_and(|t| t.ends_with("#response")),
            "the host refused the write: {doc:#}"
        );
        doc["payload"]["version"]
            .as_u64()
            .unwrap_or_else(|| panic!("the host's answer names no version: {doc:#}"))
    }

    /// Every `rooms/keys/changed/0.1` the wallet receives within `window`, and nothing else.
    /// With `first`, returns as soon as one arrives.
    async fn changed_within(&self, window: Duration, first: bool) -> Vec<Value> {
        let deadline = Instant::now() + window;
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            let frame = self
                .wallet
                .receive_next(left.as_secs().max(1))
                .await
                .expect("the wallet's session stays up");
            let Some(frame) = frame else { continue };
            let value: Value = serde_json::from_str(&frame).expect("a JSON frame");
            let doc = value.get("document").cloned().unwrap_or(value);
            if doc["type"] == TASK_ROOMS_KEYS_CHANGED_0_1 {
                seen.push(doc);
                if first {
                    break;
                }
            }
        }
        seen
    }

    fn receiving(&self, address: &str) -> bool {
        self.mock.ctx.state.room_key_watches.is_receiving(address)
    }

    async fn shutdown(self) {
        self.wallet.shutdown().await;
        self.host_task.abort();
        self.http_task.abort();
        self.mock.shutdown().await;
    }
}

/// Wait until `ready` holds, or panic with `what` after `within`.
async fn eventually(within: Duration, what: &str, mut ready: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !ready().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The one pass-on, checked: the room, member, host and latest version, signed by the VTA.
fn assert_pass_on(w: &World, doc: &Value, version: u64, address: &str) {
    assert_eq!(doc["issuer"], w.mock.vta_did(), "{doc:#}");
    assert_eq!(doc["recipient"], w.wallet_did.as_str(), "{doc:#}");
    assert!(doc["proof"].is_object(), "signed by the VTA: {doc:#}");
    let payload = doc["payload"].as_object().expect("a payload");
    assert_eq!(payload.len(), 4, "nothing but the four members: {doc:#}");
    assert_eq!(payload["roomId"], w.room.as_str());
    assert_eq!(payload["member"], w.member.as_str());
    assert_eq!(payload["host"], w.host_did.as_str());
    assert_eq!(payload["latestVersion"], version, "{doc:#}");
    assert!(
        !doc.to_string().contains(address),
        "the pass-on never names the address: {doc:#}"
    );
}

/// **The headline.** A wallet asks its VTA to watch a room; the VTA arms the host at a
/// fresh `did:peer` address and opens that address's connection at the mediator; a write
/// at the host fires the host's watch, whose `rooms/changed` the mediator routes to the
/// address; and the VTA's `rooms/keys/changed` reaches the wallet — once, and not again for
/// a second write, because the watch fired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_reaches_the_wallet_once_through_the_mediator() {
    let w = World::start(0x81, true).await;
    let address = w.arm().await;

    // (1) The mediator took a session for an address the VTA minted a moment ago and nobody
    // registered there.
    eventually(
        Duration::from_secs(30),
        "the watch address's mediator connection to open",
        async || w.receiving(&address),
    )
    .await;

    // (2) + (3): routed to the address, and on to the wallet.
    let version = w.write("n1").await;
    let changed = w.changed_within(SIGNAL_TIMEOUT, true).await;
    assert_eq!(
        changed.len(),
        1,
        "the wallet never received rooms/keys/changed for the write"
    );
    assert_pass_on(&w, &changed[0], version, &address);
    assert!(
        w.mock
            .ctx
            .state
            .room_key_watches
            .all()
            .await
            .unwrap()
            .is_empty(),
        "the fired watch is forgotten"
    );

    // One signal per arming: a second write, not re-armed, says nothing.
    w.write("n2").await;
    let again = w.changed_within(QUIET_PERIOD, false).await;
    assert!(
        again.is_empty(),
        "a second write without re-arming produced a signal: {again:#?}"
    );
    eventually(
        Duration::from_secs(10),
        "the fired watch's address connection to close",
        async || !w.receiving(&address),
    )
    .await;

    w.shutdown().await;
}

/// The host signals **before** the address's connection opens: the mediator holds the
/// `rooms/changed` for a DID that has never connected, and delivers it when the VTA's
/// supervisor opens the connection — and the wallet still gets its one pass-on.
///
/// Engineered by arming with the address supervisor not yet running (a VTA that has just
/// restarted, or one whose reconnect is backing off, is in exactly this state), waiting
/// until the mediator holds the signal, and only then starting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signal_queued_before_the_address_connects_is_delivered_when_it_does() {
    let mut w = World::start(0x82, false).await;
    let address = w.arm().await;
    assert!(
        !w.receiving(&address),
        "nothing receives at the address yet"
    );

    let version = w.write("n1").await;
    eventually(
        Duration::from_secs(20),
        "the mediator to hold the host's signal for the unconnected address",
        async || w.mock.mediator_inbox_count(&address).await >= 1,
    )
    .await;
    assert!(
        w.changed_within(Duration::from_secs(1), false)
            .await
            .is_empty(),
        "nothing can be passed on before the address is collected"
    );

    w.mock.start_watch_addresses();
    let changed = w.changed_within(SIGNAL_TIMEOUT, true).await;
    assert_eq!(
        changed.len(),
        1,
        "the queued rooms/changed was never delivered to the address, or never passed on"
    );
    assert_pass_on(&w, &changed[0], version, &address);
    let again = w.changed_within(QUIET_PERIOD, false).await;
    assert!(again.is_empty(), "one pass-on per arming: {again:#?}");

    w.shutdown().await;
}
