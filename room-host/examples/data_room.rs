//! A data room, end to end: a real host, a real client, real credentials, real MLS.
//!
//! Run it:
//!
//! ```text
//! cargo run -p room-host --example data_room
//! ```
//!
//! Nothing here is mocked. It starts the actual `room-host` router on a real TCP port and
//! drives it with `vtc_client`'s actual room methods over HTTP. Every credential is signed
//! and every signature is verified. The sealed records really are sealed — the host is
//! handed ciphertext and holds no key.
//!
//! # The four claims
//!
//! 1. **A room operation carries no session.** Every call authorizes from a credential chain
//!    the room issued. The host holds no roster and consults none — it could not; there is
//!    no code in it that does.
//! 2. **An agent holds strictly less than its human.** Alice writes; her agent reads and is
//!    refused a write. Same code, same host: the difference is entirely the chain each
//!    carries, which is what makes "give the AI read-only access for four hours" a
//!    credential rather than a policy someone has to remember to enforce.
//! 3. **A presentation is not a bearer token.** Captured and replayed by another party it is
//!    refused, because the chain is bound to whoever signed the request.
//! 4. **The host holds every byte and can neither read nor move one.** Act III seals
//!    *through* the host, and then fails to open a relocated record three different ways.

use std::net::SocketAddr;

use openmls_rust_crypto::OpenMlsRustCrypto;
use vtc_client::VtcClient;
use vtc_client::rooms::mls::{RoomGroup, RoomIdentity};
use vtc_client::rooms::sealed::SealedRoom;
use vtc_client::rooms::{CleartextContent, RoomSession, SealedContent, Visibility};
use vti_rooms_dtg::test_support::RoomFixture;

fn say(step: &str, detail: &str) {
    println!("\n\x1b[1m{step}\x1b[0m\n  {detail}");
}

fn note(detail: &str) {
    println!("  {detail}");
}

/// The refusal message out of a `trust-task-error` document.
///
/// The whole document is the right thing on the wire and the wrong thing in a demo.
fn why(e: &impl std::fmt::Display) -> String {
    let body = e.to_string();
    match body.find("\"message\":\"") {
        Some(i) => {
            let rest = &body[i + 11..];
            rest[..rest.find("\",").unwrap_or(rest.len())].to_string()
        }
        None => body,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("\n\x1b[1;4mA data room, end to end\x1b[0m");

    let (addr, _dir) = start_host().await?;
    let client = VtcClient::anonymous(&format!("http://{addr}"), "did:key:zHost");

    act_one(&client).await?;
    act_two(&client).await?;
    act_three(&client).await?;

    println!("\n\x1b[1mWhat was and was not proved\x1b[0m");
    note("Every credential above was signed and every signature verified. The host stored");
    note("ciphertext it had no key for, and authorized every call from a chain the room");
    note("itself issued — never from anything the host holds.");
    note("");
    note("A `private` room is still refused, and Act II shows the refusal rather than");
    note("hiding it. Its subject binding has to be proved in zero knowledge, and which");
    note("proof is a profile the DTG working group has not settled — so that seam is");
    note("present and empty rather than filled with something nobody agreed to.\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Act I — a shared room, over the wire
// ---------------------------------------------------------------------------

async fn act_one(client: &VtcClient) -> anyhow::Result<()> {
    println!("\n\x1b[1;4mAct I — a room, and who may act in it\x1b[0m");

    // The fixture mints the room's own key, Alice's and her agent's, then issues the
    // credentials: a VMC making Alice a member, a VAC from the room granting her
    // read/write/curate/admin, and one Alice attenuated for her agent — four hours, read
    // only, with no involvement from the room.
    let f = RoomFixture::new(vti_rooms::Visibility::Open).await;

    say(
        "1. Alice registers the room",
        "She brings the room's DID. The host stores it and learns nothing else.",
    );
    client
        .create_room(
            &f.room.room_id,
            &f.owner.did,
            Visibility::Open,
            Some(90),
            &f.owner.did,
            &f.owner.secret_multibase,
        )
        .await?;
    note("registered, epoch 1");

    let alice = session(&f, false);
    let agent = session(&f, true);

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
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await?;
        note(&format!("wrote {} at version {}", put.key, put.version));
    }

    say(
        "3. The agent reads the room as memory",
        "Alice's membership, a chain one link longer, and only `read` at the end of it.",
    );
    note(&format!(
        "Alice's chain is {} link deep; her agent's is {}",
        alice.chain_depth(),
        agent.chain_depth()
    ));
    let listing = client
        .list_records(
            &agent,
            Some("decision/"),
            None,
            &f.agent.did,
            &f.agent.secret_multibase,
        )
        .await?;
    note(&format!(
        "{} records match `decision/` — metadata only, no bodies",
        listing.records.len()
    ));
    let record = client
        .get_record(
            &agent,
            "decision/pricing-2026",
            &f.agent.did,
            &f.agent.secret_multibase,
        )
        .await?;
    note(&format!(
        "read: {}",
        record["cleartext"]["title"].as_str().unwrap_or("?")
    ));

    say(
        "4. The agent tries to write",
        "Nothing in the host says agents may not write. The chain says it, and that is enough.",
    );
    match client
        .put_record(
            &agent,
            "decision/invented",
            None,
            Some(CleartextContent {
                body: "the agent should not be able to say this".into(),
                ..Default::default()
            }),
            None,
            &f.agent.did,
            &f.agent.secret_multibase,
        )
        .await
    {
        Err(e) => note(&format!("refused: {}", why(&e))),
        Ok(_) => unreachable!("a read-only chain must not write"),
    }

    say(
        "5. Alice replays her agent's presentation",
        "A presentation says what may be done, not who is doing it — so it is bound to the signer.",
    );
    match client
        .get_record(
            &agent, // the agent's chain …
            "decision/pricing-2026",
            &f.owner.did, // … signed by Alice
            &f.owner.secret_multibase,
        )
        .await
    {
        Err(e) => note(&format!("refused: {}", why(&e))),
        Ok(_) => unreachable!("a captured presentation must not be replayable"),
    }

    say(
        "6. A stranger presents a perfectly valid chain",
        "Valid for their own room. It does not reach this one, so it confers nothing here.",
    );
    let elsewhere = RoomFixture::new(vti_rooms::Visibility::Open).await;
    let borrowed = RoomSession::new(
        &f.room.room_id,
        elsewhere.membership.clone(),
        elsewhere.owner_chain.clone(),
    )?;
    match client
        .get_record(
            &borrowed,
            "decision/pricing-2026",
            &elsewhere.owner.did,
            &elsewhere.owner.secret_multibase,
        )
        .await
    {
        Err(e) => note(&format!("refused: {}", why(&e))),
        Ok(_) => unreachable!("a chain rooted elsewhere must confer nothing"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Act II — the seam that is honestly empty
// ---------------------------------------------------------------------------

async fn act_two(client: &VtcClient) -> anyhow::Result<()> {
    println!("\n\x1b[1;4mAct II — the one thing that does not work yet\x1b[0m");

    let f = RoomFixture::new(vti_rooms::Visibility::Private).await;
    say(
        "7. A private room registers, and then refuses to be read",
        "Storing and serving are different questions. This host answers the second one no.",
    );
    client
        .create_room(
            &f.room.room_id,
            &f.owner.did,
            Visibility::Private,
            None,
            &f.owner.did,
            &f.owner.secret_multibase,
        )
        .await?;

    let session = session(&f, false).with_subject_binding("a-binding-nobody-can-check-yet");
    match client
        .get_record(
            &session,
            "anything",
            &f.owner.did,
            &f.owner.secret_multibase,
        )
        .await
    {
        Err(e) => note(&format!("refused: {}", why(&e))),
        Ok(_) => unreachable!("a private room must not be served without a ZK profile"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Act III — sealed records, through the host
// ---------------------------------------------------------------------------

async fn act_three(client: &VtcClient) -> anyhow::Result<()> {
    println!("\n\x1b[1;4mAct III — sealed, stored, and unmovable\x1b[0m");

    let f = RoomFixture::new(vti_rooms::Visibility::Attributed).await;
    client
        .create_room(
            &f.room.room_id,
            &f.owner.did,
            Visibility::Attributed,
            None,
            &f.owner.did,
            &f.owner.secret_multibase,
        )
        .await?;

    say(
        "8. Alice and Bob form the room's MLS group",
        "Bob publishes a key package over the invitation channel — never through the host.",
    );
    let mut alice_group = RoomGroup::create(&f.owner.did)?;
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_identity = RoomIdentity::new("did:key:zBob", &bob_provider)?;
    let bob_package = bob_identity.key_package(&bob_provider)?;

    let change = alice_group.add_member(bob_package)?;
    let welcome = change.welcome.expect("adding a member produces a welcome");
    let bob_group = RoomGroup::join_with(bob_identity, bob_provider, &welcome)?;
    note(&format!(
        "group has {} members, at MLS epoch {}",
        alice_group.member_count(),
        alice_group.epoch()
    ));

    // The credentials and the keys are separate objects now, and that is the honest
    // shape: the session travels to the host on every call, the keys never travel at all.
    let alice = session(&f, false);
    let alice_room = SealedRoom::new(&f.room.room_id, alice_group);
    let bob_room = SealedRoom::new(&f.room.room_id, bob_group);

    say(
        "9. Alice mints the epoch the membership change produced",
        "The host records the number and never learns the key. That is the whole of its role.",
    );
    let minted = client
        .mint_epoch(
            &alice,
            alice_room.room_epoch(),
            Some("added a member"),
            &f.owner.did,
            &f.owner.secret_multibase,
        )
        .await?;
    note(&format!(
        "room is at epoch {} — minted by an `admin` chain, not by holding a key",
        minted.epoch
    ));

    say(
        "10. Alice seals a record and stores it",
        "The key comes from the MLS exporter. What crosses the wire is below.",
    );
    let key = SealedRoom::opaque_key();
    let plaintext = b"Northwind will not be repriced before renewal. Do not share.";
    // Version 1: the record does not exist yet, and `expected_version: Some(0)` below makes
    // the host assign exactly that. The binding commits to a version chosen before the host
    // replies, which is why create-only writes are the shape that works here.
    let sealed = alice_room.seal_record(&key, 1, plaintext)?;
    note(&format!(
        "key {key}   (opaque — a descriptive key would defeat the encryption beside it)"
    ));
    note(&format!(
        "ciphertext {}…",
        &sealed.ciphertext[..44.min(sealed.ciphertext.len())]
    ));

    let put = client
        .put_record(
            &alice,
            &key,
            Some(SealedContent {
                ciphertext: sealed.ciphertext.clone(),
                nonce: sealed.nonce.clone(),
                epoch: sealed.epoch,
            }),
            None,
            Some(0),
            &f.owner.did,
            &f.owner.secret_multibase,
        )
        .await?;
    note(&format!("stored at version {}", put.version));

    say(
        "11. It comes back from the host, and Bob opens it",
        "The host served the bytes. It could not read them, and neither can anyone outside.",
    );
    let fetched = client
        .get_record(&alice, &key, &f.owner.did, &f.owner.secret_multibase)
        .await?;
    let from_host = SealedContent {
        ciphertext: fetched["sealed"].as_str().unwrap_or_default().to_string(),
        nonce: fetched["nonce"].as_str().unwrap_or_default().to_string(),
        epoch: fetched["epoch"].as_u64().unwrap_or(0) as u32,
    };
    let opened = bob_room.open_record(&key, put.version, &from_host)?;
    note(&format!("Bob reads: {}", String::from_utf8_lossy(&opened)));

    let outsider = SealedRoom::new(&f.room.room_id, RoomGroup::create("did:key:zMallory")?);
    note(match outsider.open_record(&key, put.version, &from_host) {
        Err(_) => "Mallory, holding a perfectly valid group of her own: cannot open it",
        Ok(_) => unreachable!("an outsider must not open a sealed record"),
    });

    say(
        "12. The host holds every byte and still cannot move one",
        "Each record is bound to roomId | key | version | epoch. Relocation fails loudly.",
    );
    let other = RoomFixture::new(vti_rooms::Visibility::Attributed).await;
    for (what, result) in [
        (
            "to another key",
            alice_room.open_record("other-key", put.version, &from_host),
        ),
        (
            "to another version",
            alice_room.open_record(&key, put.version + 1, &from_host),
        ),
        ("to another room", {
            let elsewhere = SealedRoom::new(&other.room.room_id, RoomGroup::create(&f.owner.did)?);
            elsewhere.open_record(&key, put.version, &from_host)
        }),
    ] {
        assert!(result.is_err(), "moving a record {what} must fail");
        note(&format!("moved {what}: does not open"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A session over the fixture's credentials, as the owner or as the agent.
fn session(f: &RoomFixture, as_agent: bool) -> RoomSession {
    let chain = if as_agent {
        f.agent_chain.clone()
    } else {
        f.owner_chain.clone()
    };
    RoomSession::new(&f.room.room_id, f.membership.clone(), chain)
        .expect("the fixture's chains are within the depth bound")
}

/// Start the real host on an ephemeral port, over a temporary store.
///
/// `did:key` resolution only — the fixture's rooms and parties are all `did:key`, so every
/// credential below verifies with no network at all. A demo that reached the network would
/// be demonstrating the network.
///
/// The returned `TempDir` must outlive the run: dropping it deletes every room.
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
