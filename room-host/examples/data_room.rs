//! A data room, end to end: a real host, a real client, real MLS.
//!
//! Run it:
//!
//! ```text
//! cargo run -p room-host --example data_room
//! ```
//!
//! Nothing here is mocked. Act I starts the actual `room-host` binary's router on a real
//! TCP port and drives it with `vtc_client`'s actual room methods over HTTP. Act II builds
//! an actual MLS group and seals records under the key it exports.
//!
//! # What the demo is trying to show
//!
//! Three claims, in the order they build on each other:
//!
//! 1. **A room operation carries no session.** Every call below authorizes from a
//!    credential chain the room issued. The host holds no roster and consults none.
//! 2. **An agent holds strictly less than its human.** Alice writes; her agent reads. The
//!    two calls are the same code against the same host — the difference is entirely in
//!    the chain each carries, which is what makes "give the AI read-only access for four
//!    hours" a credential rather than a policy someone has to enforce.
//! 3. **The host holds every byte of a sealed room and cannot read or move one.** Act II
//!    prints the ciphertext and then fails to open it four different ways.
//!
//! # What is honestly not joined up yet
//!
//! Act I runs on the `open` tier, and Act II runs locally. The join — sealed records
//! through the host — waits on cryptographic chain verification, which needs
//! `dtg_credentials::authority::verify_chain`. Until that is wired the host refuses sealed
//! rooms outright rather than serving one whose chain nobody checked, and Act III
//! demonstrates that refusal rather than papering over it.

use std::net::SocketAddr;

use base64::Engine as _;
use openmls_rust_crypto::OpenMlsRustCrypto;
use vtc_client::VtcClient;
use vtc_client::rooms::mls::{RoomGroup, RoomIdentity};
use vtc_client::rooms::sealed::SealedRoom;
use vtc_client::rooms::{CleartextContent, RoomSession, Visibility};

/// Alice, who owns the room.
const ALICE: &str = "did:key:z6MkAlicePersonKeyForTheDemoOnly";
/// Bob, a member.
const BOB: &str = "did:key:z6MkBobPersonKeyForTheDemoOnly";
/// Alice's AI agent — a different DID, holding a different chain.
const AGENT: &str = "did:key:z6MkAliceAgentKeyForTheDemoOnly";
/// Mallory, who is in no room at all.
const MALLORY: &str = "did:key:z6MkMalloryKeyForTheDemoOnly";

/// The room's own identifier. A room is a DTG node and brings its own DID — an identifier
/// the *host* chose could not survive a move to another host.
const ROOM: &str = "did:webvh:example.com:rooms:northwind";

fn say(step: &str, detail: &str) {
    println!("\n\x1b[1m{step}\x1b[0m\n  {detail}");
}

fn note(detail: &str) {
    println!("  {detail}");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("\n\x1b[1;4mA data room, end to end\x1b[0m");

    let (addr, _dir) = start_host().await?;
    let (signer_did, signer_key) = mint_signer();

    act_one(addr, &signer_did, &signer_key).await?;
    act_two()?;
    act_three(addr, &signer_did, &signer_key).await?;

    println!("\n\x1b[1mWhere this stands\x1b[0m");
    note("Act I is over HTTP against the real host. Act II is real MLS and real AEAD.");
    note("Joining them — sealed records through a host — needs chain verification, which");
    note("needs dtg-credentials 0.6 on crates.io. Until then the host refuses a sealed");
    note("room rather than serving one whose chain nobody checked (Act III).\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Act I — a shared room, over the wire
// ---------------------------------------------------------------------------

async fn act_one(addr: SocketAddr, signer_did: &str, signer_key: &str) -> anyhow::Result<()> {
    println!("\n\x1b[1;4mAct I — a room over the wire\x1b[0m");

    // `anonymous` is not a limitation being worked around. There is no token to hold: a
    // room call is authorized by its chain, and `VtcClient`'s room methods never read one.
    let client = VtcClient::anonymous(&format!("http://{addr}"), "did:key:zHostDid");

    say(
        "1. Alice registers the room",
        "She brings the room's DID. The host stores it and learns nothing else.",
    );
    client
        .create_room(
            ROOM,
            ALICE,
            Visibility::Open,
            Some(90),
            signer_did,
            signer_key,
        )
        .await?;
    note(&format!("room {ROOM} registered, epoch 1"));

    // Alice's chain: one link, straight from the room, conferring read and write.
    let alice = RoomSession::new(ROOM, "vmc:alice@northwind", vec!["vac:alice-rw".into()])?;

    say(
        "2. Alice writes two memories",
        "A shared space is only interesting once something is in it.",
    );
    for (key, title, body) in [
        (
            "decision/pricing-2026",
            "Pricing holds through Q3",
            "Agreed not to reprice before the Northwind renewal closes.",
        ),
        (
            "decision/vendor-review",
            "Vendor review moved to October",
            "The security questionnaire is the long pole, not the contract.",
        ),
    ] {
        let put = client
            .put_record(
                &alice,
                key,
                None,
                Some(CleartextContent {
                    title: Some(title.into()),
                    body: body.into(),
                    ..Default::default()
                }),
                Some(0), // create-only
                signer_did,
                signer_key,
            )
            .await?;
        note(&format!("wrote {} at version {}", put.key, put.version));
    }

    say(
        "3. Alice equips her agent",
        "A chain one link longer, conferring read alone. Same code, same host, less power.",
    );
    let agent = RoomSession::new(
        ROOM,
        "vmc:alice@northwind",
        // Leaf first: the agent's own read-only grant, then the grant Alice attenuated it
        // from. The host verifies the chain reaches the room and never widens.
        vec!["vac:agent-read-4h".into(), "vac:alice-rw".into()],
    )?;
    note(&format!(
        "Alice's chain is {} link deep; {AGENT}'s is {}",
        alice.chain_depth(),
        agent.chain_depth()
    ));

    say(
        "4. The agent reads the room as memory",
        "It lists what is there, then fetches the one record it needs.",
    );
    let listing = client
        .list_records(&agent, Some("decision/"), None, signer_did, signer_key)
        .await?;
    note(&format!(
        "{} records match `decision/` — metadata only, no bodies",
        listing.records.len()
    ));
    let record = client
        .get_record(&agent, "decision/pricing-2026", signer_did, signer_key)
        .await?;
    note(&format!(
        "read: {}",
        record["cleartext"]["title"].as_str().unwrap_or("?")
    ));

    say(
        "5. Mallory presents nothing and gets nothing",
        "Not because the host knows who Mallory is. Because there is no chain.",
    );
    // `RoomSession` refuses an empty chain before it reaches the wire, so send the document
    // by hand — the point is that the *host* refuses it too, on its own reading.
    let refused = post_raw(
        addr,
        "https://trusttasks.org/spec/rooms/records/get/0.1",
        serde_json::json!({
            "roomId": ROOM,
            "key": "decision/pricing-2026",
            "presentation": { "membership": "vmc:mallory@nowhere", "authority": [] }
        }),
    )
    .await?;
    note(&format!("host says: {refused}"));

    Ok(())
}

// ---------------------------------------------------------------------------
// Act II — what the host would hold, if it held a sealed room
// ---------------------------------------------------------------------------

fn act_two() -> anyhow::Result<()> {
    println!("\n\x1b[1;4mAct II — sealed, and unmovable\x1b[0m");

    say(
        "6. Alice and Bob form the room's MLS group",
        "Bob publishes a key package over the invitation channel — never through the host.",
    );
    let mut alice_group = RoomGroup::create(ALICE)?;

    let bob_provider = OpenMlsRustCrypto::default();
    let bob_identity = RoomIdentity::new(BOB, &bob_provider)?;
    let bob_package = bob_identity.key_package(&bob_provider)?;

    let change = alice_group.add_member(bob_package)?;
    let welcome = change.welcome.expect("adding a member produces a welcome");
    let bob_group = RoomGroup::join_with(bob_identity, bob_provider, &welcome)?;
    note(&format!(
        "group has {} members, at MLS epoch {}",
        alice_group.member_count(),
        alice_group.epoch()
    ));

    let alice_room = SealedRoom::new(
        RoomSession::new(ROOM, "vmc:alice@northwind", vec!["vac:alice-rw".into()])?,
        alice_group,
    );
    let bob_room = SealedRoom::new(
        RoomSession::new(ROOM, "vmc:bob@northwind", vec!["vac:bob-r".into()])?,
        bob_group,
    );

    say(
        "7. Alice seals a record",
        "The key comes from the MLS exporter. The host is given the bytes below.",
    );
    let key = SealedRoom::opaque_key();
    let plaintext = b"Northwind will not be repriced before renewal. Do not share.";
    let sealed = alice_room.seal_record(&key, 1, plaintext)?;
    note(&format!(
        "record key: {key}   (opaque — a descriptive key would leak)"
    ));
    note(&format!(
        "ciphertext:  {}…  ({} bytes)",
        &sealed.ciphertext[..44.min(sealed.ciphertext.len())],
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&sealed.ciphertext)
            .map(|b| b.len())
            .unwrap_or(0)
    ));

    say(
        "8. Bob opens it; the host cannot",
        "Bob derives the same key from the same group. The host has no leaf in it.",
    );
    let opened = bob_room.open_record(&key, 1, &sealed)?;
    note(&format!("Bob reads: {}", String::from_utf8_lossy(&opened)));

    let mallory_room = SealedRoom::new(
        RoomSession::new(ROOM, "vmc:forged", vec!["vac:forged".into()])?,
        RoomGroup::create(MALLORY)?,
    );
    note(match mallory_room.open_record(&key, 1, &sealed) {
        Err(_) => "Mallory, holding a perfectly valid group of her own: refused",
        Ok(_) => unreachable!("an outsider must not open a sealed record"),
    });

    say(
        "9. The host holds every byte and still cannot move one",
        "Each record is bound to roomId | key | version | epoch. Relocation fails loudly.",
    );
    for (what, result) in [
        (
            "to another key",
            alice_room.open_record("other-key", 1, &sealed),
        ),
        (
            "to another version",
            alice_room.open_record(&key, 2, &sealed),
        ),
        ("to another room", {
            let elsewhere = SealedRoom::new(
                RoomSession::new(
                    "did:webvh:example.com:rooms:other",
                    "vmc:alice@northwind",
                    vec!["vac:alice-rw".into()],
                )?,
                RoomGroup::create(ALICE)?,
            );
            elsewhere.open_record(&key, 1, &sealed)
        }),
    ] {
        assert!(result.is_err(), "moving a record {what} must fail");
        note(&format!("moved {what}: does not open"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Act III — the seam, shown rather than hidden
// ---------------------------------------------------------------------------

async fn act_three(addr: SocketAddr, signer_did: &str, signer_key: &str) -> anyhow::Result<()> {
    println!("\n\x1b[1;4mAct III — the seam\x1b[0m");

    let client = VtcClient::anonymous(&format!("http://{addr}"), "did:key:zHostDid");
    let private = "did:webvh:example.com:rooms:private";

    say(
        "10. Registering a private room succeeds",
        "The host will store it. Storing and serving are different questions.",
    );
    client
        .create_room(
            private,
            ALICE,
            Visibility::Private,
            None,
            signer_did,
            signer_key,
        )
        .await?;
    note("registered");

    say(
        "11. Reading it is refused, and the refusal says why",
        "Better to serve no sealed room than one whose authority chain nobody verified.",
    );
    let session = RoomSession::new(private, "vmc:alice@northwind", vec!["vac:alice-rw".into()])?
        .with_subject_binding("bbs-proof-that-both-describe-alice");
    match client
        .get_record(&session, "anything", signer_did, signer_key)
        .await
    {
        Err(e) => note(&format!("host says: {}", host_message(&e.to_string()))),
        Ok(_) => unreachable!("a sealed room must not be served on an unverified chain"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Start the real host on an ephemeral port, over a temporary store.
///
/// The returned `TempDir` must outlive the demo — dropping it deletes the room.
async fn start_host() -> anyhow::Result<(SocketAddr, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let app = room_host::router(room_host::open_state(dir.path())?);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    println!(
        "\n  host listening on {addr}, storing to {}",
        dir.path().display()
    );
    Ok((addr, dir))
}

/// A `did:key` to sign the Trust-Task documents with.
///
/// Signing the document and authorizing the operation are different things — the signature
/// says who sent this request, the chain says what they may do. The demo keeps them
/// visibly separate by using one throwaway signer for every call while the chains differ.
fn mint_signer() -> (String, String) {
    use ed25519_dalek::SigningKey;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness");
    let signing = SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
    );
    let secret = multibase::encode(multibase::Base::Base58Btc, seed);
    (did, secret)
}

/// Post a Trust-Task document the client would refuse to build, and return what the host
/// said about it.
async fn post_raw(
    addr: SocketAddr,
    type_uri: &str,
    payload: serde_json::Value,
) -> anyhow::Result<String> {
    let body = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": MALLORY,
        "recipient": "did:key:zHostDid",
        "payload": payload,
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/trust-tasks"))
        .json(&body)
        .send()
        .await?;
    Ok(host_message(&resp.text().await?))
}

/// Pull the human-readable message out of a `trust-task-error` document.
///
/// The whole document is the right thing on the wire and the wrong thing in a demo.
fn host_message(body: &str) -> String {
    let start = match body.find("\"message\":\"") {
        Some(i) => i + 11,
        None => return body.trim().to_string(),
    };
    let rest = &body[start..];
    let end = rest.find("\",").unwrap_or(rest.len());
    rest[..end].to_string()
}
