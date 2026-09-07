//! `pnm rooms …` — a member's surface on a data room.
//!
//! # Two parties, two transports, and why that is the whole design
//!
//! Every command here talks to **two** services, and never confuses them:
//!
//! - the operator's **VTA**, over the client's existing session, to mint a
//!   presentation ([`VtaClient::room_present`]) and to open a sealed record
//!   ([`VtaClient::room_open`]);
//! - the room's **host**, unauthenticated, carrying that presentation.
//!
//! The credentials the presentation is derived from, and the group key that
//! opens a record, stay inside the VTA. This CLI holds neither at any point,
//! which is what makes losing the laptop a smaller event than losing the agent.
//!
//! # Why a fresh presentation per call
//!
//! A presentation names *what may be done*, not who is doing it, and is bound
//! to the party that signed the request it rides. Caching one across commands
//! would mean either re-binding it (impossible without the VTA) or sending it
//! unbound (a bearer token). It is one extra local round-trip and it removes a
//! whole class of mistake, so every command mints its own.
//!
//! # What this surface deliberately does not do
//!
//! **Issue credentials.** Minting a VIC, VMC or VAC needs the *room's* signing
//! key, which is the owner's, not a member's — a different party with different
//! custody. It belongs in an owner surface and is deliberately absent here
//! rather than half-present.

use serde_json::Value;
use vta_sdk::prelude::*;
use vtc_client::VtcClient;
use vtc_client::rooms::{CleartextContent, RoomSession, Visibility};

/// Everything a room command needs to reach both parties.
///
/// The host DID is optional because an operator may not know it, and the cost
/// of not knowing is stated rather than hidden: without it the minted
/// presentation carries no audience, so it is bearer-shaped against that room
/// for its four-hour life. With it, a captured presentation is worthless to
/// anyone else.
pub struct RoomTarget<'a> {
    pub host_url: &'a str,
    pub host_did: Option<&'a str>,
    pub room_id: &'a str,
}

impl RoomTarget<'_> {
    fn client(&self) -> VtcClient {
        // The room surface carries no token — a room operation is authorized by
        // the presentation, never by a session with the host — so an anonymous
        // client is the correct one even when the host is a VTC the operator
        // also has an account on.
        VtcClient::anonymous(self.host_url, self.host_did.unwrap_or("did:key:zHost"))
    }
}

/// Mint a presentation for one action, and warn when it will be unbound.
async fn present(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    action: &str,
) -> Result<RoomSession, Box<dyn std::error::Error>> {
    if target.host_did.is_none() {
        eprintln!(
            "note: no --host-did given, so this presentation is not bound to a host. \
             Anyone who observes it can use it against this room until it expires."
        );
    }

    let minted = client
        .room_present(target.room_id, action, target.host_did, None)
        .await?;
    session_from_minted(target.room_id, &minted)
}

/// Rebuild the session from what the VTA minted.
///
/// The VTA answers with the presentation the host expects, so it is read back
/// rather than reassembled from parts — a second assembly is a second chance to
/// get the chain order wrong, and the order is load-bearing (leaf first).
///
/// Every missing member is an error rather than a default. A presentation with
/// no chain is not an empty presentation; it is a reply this client does not
/// understand, and proceeding would send the host something it will refuse for
/// reasons that read as a credential problem.
pub fn session_from_minted(
    room_id: &str,
    minted: &Value,
) -> Result<RoomSession, Box<dyn std::error::Error>> {
    let presentation = minted
        .get("presentation")
        .ok_or_else(|| format!("the VTA's reply carried no presentation: {minted}"))?;
    let membership = presentation
        .get("membership")
        .and_then(Value::as_str)
        .ok_or("the minted presentation carried no membership credential")?;
    let authority_values = presentation
        .get("authority")
        .and_then(Value::as_array)
        .ok_or("the minted presentation carried no authority chain")?;
    let authority: Vec<String> = authority_values
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    // A chain that lost links to a type mismatch is not a shorter chain — it is
    // a different grant, and a shorter one always confers less than the VTA
    // minted. Refuse rather than present it.
    if authority.len() != authority_values.len() {
        return Err("the minted authority chain contained a non-string link".into());
    }

    let mut session = RoomSession::new(room_id, membership, authority)?;
    if let Some(binding) = presentation.get("subjectBinding").and_then(Value::as_str) {
        session = session.with_subject_binding(binding);
    }
    Ok(session)
}

/// Resolve `--pin` / `--unpin` into the wire value.
///
/// Three states from two flags: pinned, unpinned, and **unchanged**. Absence has
/// to stay distinguishable from `false`, or a curation meaning to change only
/// the status would silently unpin the record on its way past.
pub fn pinned_from_flags(pin: bool, unpin: bool) -> Option<bool> {
    if pin {
        Some(true)
    } else if unpin {
        Some(false)
    } else {
        None
    }
}

/// The signer for the room-host leg: the operator's own DID and key.
///
/// A room request is signed by the party the presentation was minted *for*, and
/// the VTA minted it for the DID the CLI authenticates as. Signing with any
/// other key produces a presentation bound to somebody else, which the host
/// refuses — correctly, and confusingly, so the two are taken from one place.
pub struct RoomSigner<'a> {
    pub did: &'a str,
    pub key_multibase: &'a str,
}

/// `rooms list` — the room's records, metadata only.
pub async fn cmd_rooms_list(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    prefix: Option<&str>,
    since_version: Option<u64>,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = present(client, &target, "read").await?;
    let listing = target
        .client()
        .list_records(
            &session,
            prefix,
            since_version,
            signer.did,
            signer.key_multibase,
        )
        .await?;

    if crate::render::is_json_output() {
        crate::render::print_json(&listing.records)?;
        return Ok(());
    }
    if listing.records.is_empty() {
        println!(
            "No records{}.",
            prefix.map(|p| format!(" under `{p}`")).unwrap_or_default()
        );
        return Ok(());
    }

    println!("{} record(s):", listing.records.len());
    for r in listing.records.iter().take(limit.unwrap_or(usize::MAX)) {
        let key = r.get("key").and_then(Value::as_str).unwrap_or("?");
        let version = r.get("version").and_then(Value::as_u64).unwrap_or(0);
        let status = r.get("status").and_then(Value::as_str).unwrap_or("active");
        // On a sealed tier there is no title to show — that is the tier working,
        // not a gap, so say so rather than printing an empty column.
        let title = r
            .get("cleartext")
            .and_then(|c| c.get("title"))
            .and_then(Value::as_str)
            .unwrap_or("(sealed)");
        println!("  {key}  v{version}  {status:<10} {title}");
    }
    Ok(())
}

/// `rooms get` — one record, opened through the VTA when it is sealed.
pub async fn cmd_rooms_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = present(client, &target, "read").await?;
    let record = target
        .client()
        .get_record(&session, key, signer.did, signer.key_multibase)
        .await?;

    // An `open`-tier record arrives readable. A sealed one arrives as
    // ciphertext this process cannot decrypt, and must not try to: the group
    // key is the VTA's.
    if let Some(cleartext) = record.get("cleartext") {
        if crate::render::is_json_output() {
            crate::render::print_json(cleartext)?;
        } else {
            if let Some(title) = cleartext.get("title").and_then(Value::as_str) {
                println!("{title}\n");
            }
            println!(
                "{}",
                cleartext.get("body").and_then(Value::as_str).unwrap_or("")
            );
        }
        return Ok(());
    }

    let sealed = record.get("sealed").and_then(Value::as_str).ok_or(
        "the record carried neither cleartext nor sealed content — is this a room this \
         host serves?",
    )?;
    let nonce = record
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or("a sealed record with no nonce cannot be opened")?;
    let epoch = record.get("epoch").and_then(Value::as_u64).unwrap_or(0) as u32;
    let version = record.get("version").and_then(Value::as_u64).unwrap_or(0);

    let opened = client
        .room_open(target.room_id, key, version, sealed, nonce, epoch)
        .await
        .map_err(|e| {
            // The failure operators will actually hit, named where they will
            // read it. A record sealed under a later epoch is a missed commit,
            // and it reads like corruption if nobody says otherwise.
            format!(
                "{e}\n\nIf this mentions an epoch, your VTA has not been given the room's \
                 latest commit — ask the room's owner to deliver it, then retry."
            )
        })?;

    let plaintext = opened
        .get("plaintext")
        .and_then(Value::as_str)
        .ok_or("the VTA opened the record but returned no plaintext")?;
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, plaintext)?;
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

/// `rooms put` — write a record to an `open` room.
///
/// Sealed tiers are refused rather than half-served: sealing needs the room's
/// MLS group, which lives in the VTA, and there is no task that seals on a
/// caller's behalf. Writing cleartext into a room whose other records are
/// encrypted would be worse than refusing.
pub async fn cmd_rooms_put(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    key: &str,
    title: Option<String>,
    body: String,
    expected_version: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = present(client, &target, "write").await?;
    let put = target
        .client()
        .put_record(
            &session,
            key,
            None,
            Some(CleartextContent {
                title,
                body,
                ..Default::default()
            }),
            expected_version,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| {
            format!(
                "{e}\n\nA sealed room (`attributed` / `private`) refuses cleartext: sealing \
                 needs the room's group key, which lives in your VTA, and no task seals on a \
                 caller's behalf yet."
            )
        })?;
    println!("Wrote {} at version {}", put.key, put.version);
    Ok(())
}

/// `rooms curate` — change a record's standing.
pub async fn cmd_rooms_curate(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    key: &str,
    status: Option<String>,
    pinned: Option<bool>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if status.is_none() && pinned.is_none() {
        return Err("nothing to change — pass --status and/or --pin/--unpin".into());
    }
    // `curate` is its own grant, deliberately not implied by `write`: deciding
    // what a room's shared knowledge is worth is a different act from adding to
    // it. So the presentation is minted for `curate`, and a member who only
    // writes is refused here rather than at the host.
    let session = present(client, &target, "curate").await?;

    let out = target
        .client()
        .curate_record(
            &session,
            key,
            status,
            pinned,
            reason,
            signer.did,
            signer.key_multibase,
        )
        .await?;
    println!(
        "{} is now {} at version {}{}",
        out.key,
        serde_json::to_value(out.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "?".into()),
        out.version,
        if out.pinned { " (pinned)" } else { "" }
    );
    Ok(())
}

/// `rooms renew` — mint the next epoch, which is what keeps a room live.
///
/// Needs `admin`. It is the same act as ordinary use, and it is the whole
/// defence against a hostile succession claim: an owner who renews is
/// structurally safe without thinking about it.
pub async fn cmd_rooms_renew(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    epoch: u32,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = present(client, &target, "admin").await?;
    let minted = target
        .client()
        .mint_epoch(
            &session,
            epoch,
            reason.as_deref(),
            signer.did,
            signer.key_multibase,
        )
        .await?;
    println!("Room {} is at epoch {}", minted.room_id, minted.epoch);
    Ok(())
}

/// `rooms create` — register a room with a host.
///
/// The only command here that needs no presentation: the room has issued
/// nothing yet, so there is no chain to present. The host checks the request's
/// own proof instead, which is why this must be signed as the owner it names.
pub async fn cmd_rooms_create(
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    visibility: &str,
    retention_days: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let visibility: Visibility = serde_json::from_value(Value::String(visibility.to_string()))
        .map_err(|_| "visibility must be one of: open, attributed, private")?;

    target
        .client()
        .create_room(
            target.room_id,
            signer.did,
            visibility,
            retention_days,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| {
            format!(
                "{e}\n\nA community host decides whose rooms it stores. If this says \
                 `not-a-member`, you are not a member there; if it says \
                 `private-tier-not-enabled`, that community has not turned the tier on."
            )
        })?;
    println!("Registered {} as {}", target.room_id, signer.did);
    println!(
        "  Next: the room must issue you a membership and an authority credential before \
         you can act in it."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minted(authority: Value) -> Value {
        json!({
            "presentation": {
                "membership": "vmc-blob",
                "authority": authority,
            },
            "expiresAt": "2026-09-07T16:00:00Z",
        })
    }

    #[test]
    fn a_minted_presentation_becomes_a_session() {
        let session = session_from_minted("did:webvh:room", &minted(json!(["leaf", "root"])))
            .expect("a well-formed reply rebuilds");
        assert_eq!(session.room_id(), "did:webvh:room");
        assert_eq!(session.chain_depth(), 2, "leaf first, root last");
    }

    /// A private room's presentation carries the same-subject proof, and losing
    /// it on the way through would turn a valid call into a refusal the
    /// operator cannot explain.
    #[test]
    fn a_subject_binding_survives_the_rebuild() {
        let mut m = minted(json!(["leaf"]));
        m["presentation"]["subjectBinding"] = json!("zk-proof-blob");
        let session =
            session_from_minted("did:webvh:room", &m).expect("a private presentation rebuilds");
        assert_eq!(session.chain_depth(), 1);
    }

    /// Each missing member is refused rather than defaulted. A reply this
    /// client does not understand must not become a request the host refuses
    /// for reasons that read as a credential problem.
    #[test]
    fn an_unreadable_reply_is_refused_rather_than_guessed() {
        assert!(
            session_from_minted("r", &json!({})).is_err(),
            "no presentation"
        );
        assert!(
            session_from_minted("r", &json!({ "presentation": { "authority": ["a"] } })).is_err(),
            "no membership"
        );
        assert!(
            session_from_minted("r", &json!({ "presentation": { "membership": "m" } })).is_err(),
            "no chain"
        );
        assert!(
            session_from_minted("r", &minted(json!([]))).is_err(),
            "an empty chain authorizes nothing and must not be sent"
        );
    }

    /// A link that is not a string would otherwise be filtered out, silently
    /// shortening the chain — and a shorter chain confers less than the VTA
    /// minted, so the call would fail somewhere far from the cause.
    #[test]
    fn a_malformed_link_does_not_silently_shorten_the_chain() {
        let err = session_from_minted("r", &minted(json!(["leaf", 7])))
            .expect_err("a non-string link is refused");
        assert!(
            err.to_string().contains("non-string"),
            "the error must name the cause: {err}"
        );
    }

    #[test]
    fn pin_flags_keep_unchanged_distinct_from_unpinned() {
        assert_eq!(pinned_from_flags(true, false), Some(true));
        assert_eq!(pinned_from_flags(false, true), Some(false));
        assert_eq!(
            pinned_from_flags(false, false),
            None,
            "neither flag must leave the pin alone, not clear it"
        );
    }
}
