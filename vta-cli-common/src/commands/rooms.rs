//! `pnm rooms …` — a member's surface on a data room.
//!
//! # Two parties, two transports, and why that is the whole design
//!
//! Every command here talks to **two** services, and never confuses them:
//!
//! - the operator's **VTA**, over the client's existing session, to complete each
//!   host-bound request **as the member** ([`VtaClient::room_act`],
//!   `rooms/keys/act/0.1`), to seal a record body signed as the member
//!   ([`VtaClient::room_seal_as_principal`]) and to open a sealed record
//!   ([`VtaClient::room_open`]);
//! - the room's **host**, unauthenticated, receiving the completed document unchanged.
//!
//! # The member is the persona, never this client
//!
//! A room admitted the operator's **persona** — a DID their VTA holds — not this CLI's
//! session key. So the record verbs (`list`, `get`, `put`, `curate`, the `rooms/info`
//! lookup and `keys commit --host`) build the request unsigned and have the VTA complete
//! it as the persona: the persona's own authority narrowed to the one action, the persona
//! as `issuer` and signer. The host records the persona, and this client's DID reaches it
//! nowhere. File transfer works the same way (`rooms/blobs/*/0.2`): the begin, the record,
//! the read and — in direct mode — the commit are completed as the persona, and a proxied
//! upload's chunks are signed by a single-use upload key minted for that upload. `renew`
//! still presents for this client ([`VtaClient::room_present`]) and signs with its own
//! key; it moves separately.
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
//! custody. The owner's surface is [`super::rooms_custody`], whose verbs are
//! calls to the VTA holding that key.

use serde_json::Value;
use vta_sdk::prelude::*;
use vtc_client::VtcClient;
use vtc_client::rooms::body::{
    RecordLocation, SealedRecordBody, VerifiedRecordBody, verify_record_body,
};
use vtc_client::rooms::{CleartextContent, RoomSession, SealedContent, Visibility};

/// Everything a room command needs to reach both parties.
///
/// The host DID is optional because an operator may not know it, and it names the
/// **recipient** of the document — nothing more. It used to be passed as the presentation's
/// `audience` as well, on the reading that this bound the presentation to one host. It never
/// could: see [`present`]. A presentation is bound to whoever will sign the request, always,
/// so there is no unbound case for an operator to be warned about.
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

/// Mint a presentation for one action.
///
/// # There is no party to name here, and there used to be two
///
/// This passed `target.host_did` as the presentation's `audience` until that was found
/// never to work: `audience` named the party that had to *present* the credential, not the
/// one it was addressed to, so filling it with a host's DID named somebody no presenter can
/// ever be, and every request was refused. Omitting `--host-did` "worked" only because an
/// absent audience skipped the check — so the flag's two states were *broken* and
/// *unprotected*, with nothing in between.
///
/// Neither the field nor this parameter survives. A presentation is granted to the caller
/// the VTA authenticated and a host refuses a chain granting to anyone else, so who may
/// present is established rather than declared; and it is bound to a *room* rather than a
/// host, so there is no destination to name either. `--host-did` keeps its real job:
/// naming the document's `recipient`.
///
/// See `rooms/keys/present/0.2`, which removed both members, and
/// trustoverip/dtgwg-trust-tasks-tf#414.
async fn present(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    action: &str,
) -> Result<RoomSession, Box<dyn std::error::Error>> {
    let minted = client.room_present(target.room_id, action).await?;
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

/// Send one room request to the host **as the member**: built here without presentation
/// or proof, completed by the VTA with `rooms/keys/act/0.1`, sent unchanged. Returns the
/// member the VTA acted as and the host's response payload.
///
/// Nothing this client holds goes to the host: not its DID, not its key.
async fn act_and_send(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    act_and_send_as(client, target, type_uri, payload, None).await
}

/// [`act_and_send`], naming the member to act as — required for a document that names
/// no room (a download chunk, a direct upload's commit or abort), whose authority is
/// the transfer the member's own request opened.
async fn act_and_send_as(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
    issuer: Option<&str>,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    let host_did = target.host_did.unwrap_or("did:key:zHost");
    let document = vta_sdk::client::unsigned_room_request(type_uri, host_did, issuer, payload)?;
    let completed = client.room_act(&document).await.map_err(|e| {
        let text = e.to_string();
        let hint = if text.contains("principalAmbiguous") {
            "\n\nYou may act as more than one member of this room: act from the context of \
             the one you mean."
        } else if text.contains("notAMember") {
            "\n\nYour VTA holds no credential this room issued to a persona you may act as. \
             The owner issues them with `pnm rooms owner issue-membership` and \
             `issue-authority --store`."
        } else if text.contains("actionNotHeld") {
            "\n\nYour own credentials for this room do not confer that action."
        } else {
            ""
        };
        format!("{e}{hint}")
    })?;
    let principal = completed.principal.to_string();
    let document = serde_json::to_value(&completed.document)?;
    let reply = target.client().send_signed_room_document(&document).await?;
    Ok((principal, reply))
}

/// [`act_and_send`], with the response parsed into its wire type.
pub(crate) async fn act_and_send_parsed<T: serde::de::DeserializeOwned>(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
) -> Result<T, Box<dyn std::error::Error>> {
    let (_, reply) = act_and_send(client, target, type_uri, payload).await?;
    parse_reply(type_uri, reply)
}

/// Parse a host's response payload into its wire type, naming the task when it does not fit.
fn parse_reply<T: serde::de::DeserializeOwned>(
    what: &str,
    value: Value,
) -> Result<T, Box<dyn std::error::Error>> {
    serde_json::from_value(value)
        .map_err(|e| format!("the host's {what} response is not one this client reads: {e}").into())
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

/// `rooms list` — the room's records, metadata only, read as the member.
pub async fn cmd_rooms_list(
    client: &VtaClient,
    target: RoomTarget<'_>,
    prefix: Option<&str>,
    since_version: Option<u64>,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the listing to its END, then let `limit` decide how much to PRINT.
    // A host pages, and absence of the cursor is the only end-of-listing signal
    // — taking the first page would print "3 record(s)" over a room holding
    // three hundred, which is the failure this whole member exists to prevent.
    let mut listing = list_page(client, &target, prefix, since_version, None).await?;
    let mut cursor = listing.cursor.clone();
    while let Some(c) = cursor {
        let next = list_page(client, &target, prefix, since_version, Some(&c)).await?;
        cursor = next.cursor.clone();
        listing.records.extend(next.records);
    }

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

    let shown = limit.unwrap_or(usize::MAX).min(listing.records.len());
    if shown < listing.records.len() {
        println!(
            "{} record(s), showing {shown} — pass a larger --limit for the rest:",
            listing.records.len()
        );
    } else {
        println!("{} record(s):", listing.records.len());
    }
    for r in listing.records.iter().take(shown) {
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

/// One page of `rooms/records/list`, as the member.
async fn list_page(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    prefix: Option<&str>,
    since_version: Option<u64>,
    cursor: Option<&str>,
) -> Result<vti_rooms::wire::ListRecordsResponse, Box<dyn std::error::Error>> {
    let mut payload = serde_json::json!({ "roomId": target.room_id });
    if let Some(p) = prefix {
        payload["prefix"] = serde_json::json!(p);
    }
    if let Some(v) = since_version {
        payload["sinceVersion"] = serde_json::json!(v);
    }
    if let Some(c) = cursor {
        payload["cursor"] = serde_json::json!(c);
    }
    let (_, reply) = act_and_send(
        client,
        target,
        vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
        payload,
    )
    .await?;
    parse_reply("rooms/records/list", reply)
}

/// `rooms get` — one record, read as the member and opened through the VTA when it is
/// sealed.
///
/// A sealed record is shown only after its body checks out: the author's signature, the
/// location it was signed for, and on `attributed` that the body's signer is the author the
/// host recorded ([`verify_record_body`]) — the persona, for a record a member's own client
/// wrote. One that fails is refused, never shown with a warning.
pub async fn cmd_rooms_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, record) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
        serde_json::json!({ "roomId": target.room_id, "key": key }),
    )
    .await?;

    // An `open`-tier record arrives readable. A sealed one arrives as
    // ciphertext this process cannot decrypt, and must not try to: the group
    // key is the VTA's.
    if let Some(cleartext) = record.get("cleartext") {
        if crate::render::is_json_output() {
            crate::render::print_json(cleartext)?;
        } else {
            if let Some(title) = cleartext.get("title").and_then(Value::as_str) {
                println!("{}\n", inert(title));
            }
            println!(
                "{}",
                inert(cleartext.get("body").and_then(Value::as_str).unwrap_or(""))
            );
        }
        return Ok(());
    }

    let sealed: SealedContent =
        serde_json::from_value(record.get("sealed").cloned().ok_or(
            "the record carried neither cleartext nor sealed content; it may be retracted",
        )?)
        .map_err(|e| format!("the host's sealed record is malformed: {e}"))?;
    let version = record
        .get("version")
        .and_then(Value::as_u64)
        .ok_or("the host's record carried no version")?;
    let author = record.get("author").and_then(Value::as_str);

    let body = open_and_verify(client, &target, key, version, &sealed, author).await?;
    let body = body.body();
    if crate::render::is_json_output() {
        crate::render::print_json(body)?;
        return Ok(());
    }
    if let Some(title) = &body.title {
        println!("{}\n", inert(title));
    }
    if let Some(text) = &body.body {
        println!("{}", inert(text));
    }
    if let Some(file) = &body.file {
        println!(
            "\nFile: {} ({} bytes). Fetch it with `pnm rooms file get {key}`.",
            inert(&file.name),
            file.size
        );
    }
    println!("\nWritten by {} at version {version}.", body.author);
    Ok(())
}

/// `rooms put` — write a record, as the member.
///
/// On an `open` room the record goes in the clear. On `attributed` and `private` it is a
/// [`SealedRecordBody`] naming the member as author, which the VTA signs **as the member**
/// and seals (`rooms/keys/seal/0.2`, `signAsPrincipal`), so the host never sees it and
/// every reader can check that the member wrote it.
pub async fn cmd_rooms_put(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
    title: Option<String>,
    body: String,
    expected_version: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sealed_tier, member) = room_tier(client, &target).await?;

    if !sealed_tier {
        let mut payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "cleartext": CleartextContent { title, body, ..Default::default() },
        });
        if let Some(v) = expected_version {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        let (_, reply) = act_and_send(
            client,
            &target,
            vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
            payload,
        )
        .await?;
        let put: vti_rooms::wire::PutRecordResponse = parse_reply("rooms/records/put", reply)?;
        println!("Wrote {} at version {} as {member}", put.key, put.version);
        return Ok(());
    }

    let mut content = SealedRecordBody::new(
        RecordLocation {
            room_id: target.room_id,
            key,
            version: 1,
        },
        &member,
    );
    content.title = title;
    content.body = Some(body);
    let version = write_sealed(client, &target, content, expected_version).await?;
    println!("Wrote {key} at version {version}, sealed and signed by {member}");
    Ok(())
}

/// `rooms curate` — change a record's standing.
pub async fn cmd_rooms_curate(
    client: &VtaClient,
    target: RoomTarget<'_>,
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
    // it. So the request is completed for `curate`, and a member who only
    // writes is refused by their own VTA rather than at the host.
    let mut payload = serde_json::json!({ "roomId": target.room_id, "key": key });
    if let Some(s) = status {
        payload["status"] = serde_json::json!(s);
    }
    if let Some(p) = pinned {
        payload["pinned"] = serde_json::json!(p);
    }
    if let Some(r) = reason {
        payload["reason"] = serde_json::json!(r);
    }
    let (_, reply) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
        payload,
    )
    .await?;
    let out: vti_rooms::wire::CurateRecordResponse = parse_reply("rooms/records/curate", reply)?;
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

/// `rooms renew` — mint the next epoch, which is what keeps an **open** room live.
///
/// Needs `admin`. It is the same act as ordinary use, and it is the whole
/// defence against a hostile succession claim: an owner who renews is
/// structurally safe without thinking about it.
///
/// Refuses an `attributed` or `private` room ([`refuse_sealed_renew`]): there the room's
/// epoch is its MLS group's plus one, and a mint without a commit moves the host and no
/// member — every write is then refused as sealed under a superseded epoch.
pub async fn cmd_rooms_renew(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    epoch: u32,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // The tier first, under `read`, before anything is minted: rooms/keys/act/0.1
    // producer item 4 — a client never asks to mint a sealed room's epoch.
    let read = present(client, &target, "read").await?;
    let info = target
        .client()
        .room_info(&read, signer.did, signer.key_multibase)
        .await
        .map_err(|e| format!("could not read the room's tier (rooms/info): {e}"))?;
    refuse_sealed_renew(&wire_str(&info.visibility), &target)?;

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

/// `pnm rooms renew` is an open room's renewal only. A sealed room (`attributed` or
/// `private`) renews through the owner's key holder, which advances the group with a commit
/// and the host with it (`rooms/owner/group/renew/0.1`); a bare mint would brick the room
/// for writing while looking like success.
fn refuse_sealed_renew(visibility: &str, target: &RoomTarget<'_>) -> Result<(), String> {
    if visibility == "open" {
        return Ok(());
    }
    Err(format!(
        "room {room} is `{visibility}`: its epoch advances only with a commit of its group, \
         which this client cannot make, and a bare mint would leave every member unable to \
         write. Renew it from the owner's VTA instead:\n\n  pnm rooms owner group-renew \
         --room {room} --host-did {host_did}",
        room = target.room_id,
        host_did = target.host_did.unwrap_or("<the host's DID>"),
    ))
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

// ─── Files ───────────────────────────────────────────────────────────────
//
// Sealing and opening a room file locally, with one file's key from the VTA
// (`rooms/keys/file-key/0.1`). The bytes never pass through the VTA; what the
// VTA releases opens this one file and nothing else.
//
// What is written is the upload's whole input and nothing more: the sealed
// chunks, the blob manifest a host checks, and the file manifest that belongs
// inside the sealed record body. Uploading them is `rooms/blobs/upload/*` and
// a record put naming the blob.

/// The blob manifest beside the chunks.
const BLOB_MANIFEST: &str = "blob.json";
/// The file manifest — the sealed record body's `file` member.
const FILE_MANIFEST: &str = "file.json";
/// The sealed chunks, in index order.
const CHUNKS_DIR: &str = "chunks";

fn chunk_path(dir: &std::path::Path, index: usize) -> std::path::PathBuf {
    dir.join(CHUNKS_DIR).join(format!("{index:06}.bin"))
}

fn file_key_bytes(
    resp: &trust_tasks_rs::specs::rooms::keys::file_key::v0_1::Response,
) -> Result<vti_rooms::files::FileKey, Box<dyn std::error::Error>> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(resp.key.as_str())?;
    bytes
        .try_into()
        .map_err(|_| "the VTA returned a file key that is not 32 bytes".into())
}

/// `rooms file seal` — seal a local file for a room, ready to upload.
pub async fn cmd_rooms_file_seal(
    client: &VtaClient,
    room_id: &str,
    path: &std::path::Path,
    out: &std::path::Path,
    padme: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::files::{self, FileBinding, Padding};

    if out.exists() {
        return Err(format!("{} already exists; choose a new directory", out.display()).into());
    }
    let plaintext = std::fs::read(path)?;
    // The name is the uploader's and is sealed: only members see it.
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file has no usable name")?;

    // A fresh id for every file: the segment nonces are counters, so two files
    // under one key would reuse them.
    let file_id = files::new_file_id();
    let resp = client
        .room_file_key(room_id, &files::encode_file_id(&file_id), None)
        .await?;
    let key = file_key_bytes(&resp)?;
    let sealed = files::seal_file(
        &key,
        FileBinding {
            room_id: room_id.to_string(),
            file_id,
            epoch: resp.epoch.get(),
            segment_size: files::DEFAULT_SEGMENT_SIZE,
        },
        name,
        None,
        &plaintext,
        if padme { Padding::Padme } else { Padding::None },
    )?;
    std::fs::create_dir_all(out.join(CHUNKS_DIR))?;
    for (i, chunk) in sealed.chunks.iter().enumerate() {
        std::fs::write(chunk_path(out, i), chunk)?;
    }
    std::fs::write(
        out.join(BLOB_MANIFEST),
        serde_json::to_vec_pretty(&sealed.blob)?,
    )?;
    std::fs::write(
        out.join(FILE_MANIFEST),
        serde_json::to_vec_pretty(&sealed.file)?,
    )?;
    println!(
        "Sealed {} ({} bytes) under epoch {} into {}\n  blobRef  {}\n  chunks   {} of {} bytes",
        name,
        sealed.file.size,
        sealed.file.epoch,
        out.display(),
        sealed.file.blob_ref,
        sealed.blob.chunks.chunk_count,
        sealed.blob.chunks.chunk_size,
    );
    println!(
        "  {FILE_MANIFEST} goes inside the sealed record body; it names the file and is never \
         sent to the host in the clear."
    );
    Ok(())
}

/// `rooms file open` — open a sealed file directory, refusing one that is not
/// the file its author signed.
pub async fn cmd_rooms_file_open(
    client: &VtaClient,
    room_id: &str,
    dir: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::files::{self, BlobManifest, FileManifest};

    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    let file: FileManifest = serde_json::from_slice(&std::fs::read(dir.join(FILE_MANIFEST))?)?;
    let blob: BlobManifest = serde_json::from_slice(&std::fs::read(dir.join(BLOB_MANIFEST))?)?;
    // The file manifest is the author's; the blob manifest is whoever served it.
    // Before a byte is trusted: it is the blob the author named, and its chunk size
    // and count are the ones the author's segment size and length give.
    file.check_blob(&blob)?;
    let mut chunks = Vec::with_capacity(blob.chunks.chunk_count as usize);
    for (i, expected) in blob.chunks.chunk_digests.iter().enumerate() {
        let chunk = std::fs::read(chunk_path(dir, i))?;
        if !files::same_digest(&files::digest_multibase(&chunk), expected) {
            return Err(format!("chunk {i} does not match the manifest").into());
        }
        chunks.push(chunk);
    }

    let resp = client
        .room_file_key(room_id, &file.file_id, Some(file.epoch))
        .await?;
    let key = file_key_bytes(&resp)?;
    let plaintext = files::open_file(&key, room_id, &file, &blob, &chunks)?;

    // Written beside the target and moved into place, so a failure leaves nothing that
    // looks like the file.
    let tmp = out.with_extension("partial");
    std::fs::write(&tmp, &plaintext)?;
    std::fs::rename(&tmp, out)?;
    println!(
        "Opened {} ({} bytes) into {} — the digest its author signed matches.",
        // Untrusted text from another member: escaped, so it cannot drive the terminal.
        file.name.escape_debug(),
        plaintext.len(),
        out.display()
    );
    Ok(())
}

// ─── Sealed records and files, end to end ────────────────────────────────

/// How many times a sealed write re-seals for the version the host actually assigned before
/// giving up. Versions come from a room-wide counter, so each retry loses only to a write
/// that landed between this one's seal and its put.
const SEALED_WRITE_ATTEMPTS: usize = 4;

/// Strip what could drive a terminal from text another member wrote: control characters,
/// escape sequences among them, except newline and tab.
fn inert(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// A fresh opaque record key. On a sealed tier a key MUST say nothing about the record.
fn opaque_key() -> String {
    let bytes: [u8; 16] = rand::random();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// The serialized string of a generated newtype (a digest, a transfer id).
fn wire_str<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Whether the room seals its records, from `rooms/info` read as the member — and which
/// member the VTA acted as, which is the author a sealed body names.
async fn room_tier(
    client: &VtaClient,
    target: &RoomTarget<'_>,
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    let (member, reply) = act_and_send(
        client,
        target,
        trust_tasks_rs::specs::rooms::info::v0_1::Payload::TYPE_URI,
        serde_json::json!({ "roomId": target.room_id }),
    )
    .await
    .map_err(|e| format!("could not read the room's tier (rooms/info): {e}"))?;
    let visibility = reply
        .get("visibility")
        .and_then(Value::as_str)
        .ok_or("the host's rooms/info response names no visibility")?;
    Ok((visibility != "open", member))
}

/// Have the VTA sign `content` **as the member** and seal it (`rooms/keys/seal/0.2`), and
/// put it as the member (`rooms/keys/act/0.1`), re-sealing at the version the host assigned
/// whenever that is not the one sealed for. Returns the version written.
///
/// The record's associated data and its signed body both name the version, and the host
/// assigns it from a room-wide counter, so the version is predicted from the room's head and
/// a miss is corrected by a rewrite. Until that rewrite lands the record does not open,
/// which is why a write that runs out of attempts says so and names the key.
async fn write_sealed(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    content: SealedRecordBody,
    expected_version: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>> {
    write_sealed_naming(client, target, content, expected_version, None).await
}

/// [`write_sealed`], naming `blobs` committed in the room (`rooms/records/put/0.2`).
async fn write_sealed_naming(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    content: SealedRecordBody,
    expected_version: Option<u64>,
    blobs: Option<Vec<String>>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let head = list_page(client, target, None, None, None)
        .await?
        .head_version
        .unwrap_or(0);

    let key = content.key.clone();
    let mut intended = head + 1;
    let mut expected = expected_version;
    let mut landed = 0;
    for _ in 0..SEALED_WRITE_ATTEMPTS {
        // Unsigned: the VTA signs it as its author, the member, before sealing.
        let unsigned = serde_json::to_vec(&content.clone().at_version(intended))?;
        let sealed = client
            .room_seal_as_principal(target.room_id, &key, intended, &unsigned)
            .await?
            .sealed;
        let mut payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "sealed": {
                "ciphertext": sealed.ciphertext,
                "nonce": sealed.nonce,
                "epoch": sealed.epoch.get(),
            },
        });
        if let Some(v) = expected {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        let put_type = match &blobs {
            Some(b) => {
                payload["blobs"] = serde_json::json!(b);
                vti_rooms::wire::ROOMS_RECORDS_PUT_V2_TYPE
            }
            None => vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
        };
        let (_, reply) = act_and_send(client, target, put_type, payload)
            .await
            .map_err(|e| put_refused(e, target))?;
        let put: vti_rooms::wire::PutRecordResponse = parse_reply("rooms/records/put", reply)?;
        landed = put.version;
        if landed == intended {
            return Ok(landed);
        }
        // Another write took the predicted version. The record is stored but sealed for the
        // wrong one, so it does not open; rewrite it, and only over what just landed.
        expected = Some(landed);
        intended = landed + 1;
    }
    Err(format!(
        "{key} is stored at version {landed} but sealed for another version, so it does not \
         open: the room kept moving under {SEALED_WRITE_ATTEMPTS} attempts. Write it again \
         with --expected-version {landed}."
    )
    .into())
}

/// The `pnm rooms keys commit` that brings this VTA's group up to the room's epoch,
/// with the target's own values. `--host-did` only when the operator gave one: a VTC
/// needs it, another host may not have one to give.
fn keys_commit_command(target: &RoomTarget<'_>) -> String {
    let mut cmd = format!(
        "pnm rooms keys commit --room {} --host {}",
        target.room_id, target.host_url
    );
    if let Some(did) = target.host_did {
        cmd.push_str(&format!(" --host-did {did}"));
    }
    cmd
}

/// `rooms/records/put` refused `e`: when the host says the record was sealed under an
/// epoch the room has moved past (the declared `epochMismatch`), say what happened and
/// print the command that catches up. Anything else is returned as it was.
fn put_refused(
    e: Box<dyn std::error::Error>,
    target: &RoomTarget<'_>,
) -> Box<dyn std::error::Error> {
    let refusal = e
        .downcast_ref::<vtc_client::VtcError>()
        .and_then(vtc_client::git_ns::task_error);
    match refusal {
        Some((code, message)) => match put_refusal_hint(&code, &message, target) {
            Some(hint) => hint.into(),
            None => e,
        },
        None => e,
    }
}

/// The operator-facing text for a `rooms/records/put` refusal `code`, when there is one.
fn put_refusal_hint(code: &str, message: &str, target: &RoomTarget<'_>) -> Option<String> {
    use trust_tasks_rs::specs::rooms::records::put;
    let epoch_mismatch = [
        put::v0_1::error_codes::EPOCH_MISMATCH.code,
        put::v0_2::error_codes::EPOCH_MISMATCH.code,
    ];
    if !epoch_mismatch.contains(&code) {
        return None;
    }
    Some(format!(
        "the host refused the record: {message}\n\n\
         The room has moved on to a newer epoch — it was renewed, or its membership changed — \
         and this VTA has not applied the commit that moved it, so it sealed the record under \
         the old epoch. Nothing was written. Catch up, then write again:\n\n  {}",
        keys_commit_command(target)
    ))
}

/// The operator-facing text for a `rooms/keys/open` refusal.
fn open_refusal_hint(e: &VtaError, target: &RoomTarget<'_>) -> String {
    use trust_tasks_rs::specs::rooms::keys::open::v0_1::error_codes::UNKNOWN_EPOCH;
    epoch_refusal_hint(e, target, UNKNOWN_EPOCH.code, Sealed::Record)
}

/// The operator-facing text for a `rooms/keys/file-key` refusal, as `pnm rooms file
/// get` and `file open` print it — the same remedies a record's refusal names.
fn file_key_refusal_hint(e: &VtaError, target: &RoomTarget<'_>) -> String {
    use trust_tasks_rs::specs::rooms::keys::file_key::v0_1::error_codes::UNKNOWN_EPOCH;
    epoch_refusal_hint(e, target, UNKNOWN_EPOCH.code, Sealed::File)
}

/// What a refused epoch had sealed, for the wording of [`epoch_refusal_hint`].
#[derive(Clone, Copy)]
enum Sealed {
    Record,
    File,
}

impl Sealed {
    fn noun(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::File => "file",
        }
    }
}

/// The remedy for a refused epoch, from the declared `unknownEpoch` (`code`) and its
/// `details.reason`.
///
/// The epoch cases have opposite remedies, so they are told apart by reason —
/// `notDelivered` (catch up), `beyondChain` (backfill) and, where the task's
/// specification declares it, `removed` (no commit will help) — never by the message.
/// `rooms/keys/file-key/0.1` declares only the first two, so a removed member's file
/// arrives as `notDelivered`, with the VTA's message saying it was a removal; the hint
/// says to look for that. The text checks are for a VTA that predates the reasons.
fn epoch_refusal_hint(e: &VtaError, target: &RoomTarget<'_>, code: &str, sealed: Sealed) -> String {
    let noun = sealed.noun();
    let reason = (e.rejection_code() == Some(code))
        .then(|| e.rejection_details())
        .flatten()
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str);
    let text = e.to_string();
    let backfill = || {
        format!(
            "The {noun} is older than any key this VTA holds — it was written before you \
             joined. Fetch the room's history: `pnm rooms keys backfill --room {} --host-did \
             {}`.",
            target.room_id,
            target.host_did.unwrap_or("<host-did>")
        )
    };
    let hint = match reason {
        Some("removed") => {
            let at = e
                .rejection_details()
                .and_then(|d| d.get("removedAtEpoch"))
                .and_then(Value::as_u64)
                .map(|n| format!(" at epoch {n}"))
                .unwrap_or_default();
            format!(
                "You were removed from this room's group{at}. {}s sealed since then will \
                 never open for you, and no commit will change that; what was sealed before \
                 your removal still opens. Rejoining takes a fresh invitation from the room's \
                 owner.",
                capitalised(noun)
            )
        }
        Some("notDelivered") => format!(
            "The {noun} is newer than this VTA's group: a commit has not been applied here. \
             Catch up, then try again:\n\n  {}{}",
            keys_commit_command(target),
            match sealed {
                // `removed` has a reason of its own for a record.
                Sealed::Record => "",
                Sealed::File => {
                    "\n\nIf the VTA says above that you were removed from the room's group, \
                     catching up will not help: files sealed since your removal will never \
                     open for you, and what was sealed before it still opens. Rejoining takes \
                     a fresh invitation from the room's owner."
                }
            }
        ),
        Some("beyondChain") => backfill(),
        _ if text.contains("cannot reach") => backfill(),
        _ if text.contains("has not been delivered") => format!(
            "The {noun} is newer than this VTA's group. Catch up with `{}`; if that says you \
             were removed, nothing sealed after your removal will open.",
            keys_commit_command(target)
        ),
        _ => format!("The {noun} did not open with any key this VTA holds."),
    };
    format!("{e}\n\n{hint}")
}

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// Open a sealed record through the VTA and check its body before anything in it is used.
async fn open_and_verify(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    key: &str,
    version: u64,
    sealed: &SealedContent,
    host_author: Option<&str>,
) -> Result<VerifiedRecordBody, Box<dyn std::error::Error>> {
    let opened = client
        .room_open(
            target.room_id,
            key,
            version,
            &sealed.ciphertext,
            &sealed.nonce,
            sealed.epoch,
        )
        .await
        // The failures operators will actually hit, named where they will read them. Each
        // reads like corruption if nobody says otherwise.
        .map_err(|e| open_refusal_hint(&e, target))?;
    let plaintext = opened
        .get("plaintext")
        .and_then(Value::as_str)
        .ok_or("the VTA opened the record but returned no plaintext")?;
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, plaintext)?;

    let resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::from_optional(
        vta_sdk::resolver::shared_did_resolver_from_env().await.ok(),
    );
    let location = RecordLocation {
        room_id: target.room_id,
        key,
        version,
    };
    Ok(verify_record_body(&bytes, location, host_author, &resolver)
        .await
        .map_err(|e| format!("refusing record {key}: {e}"))?)
}

/// The part size a direct upload is cut into: one part up to [`SINGLE_PART_MAX`], else
/// parts of this size (storage's multipart floor is 5 MiB).
const DIRECT_PART: usize = 8 * 1024 * 1024;
/// The largest blob sent as one direct part.
const SINGLE_PART_MAX: usize = 16 * 1024 * 1024;
/// How many times a direct upload asks again for targets before giving up.
const DIRECT_BEGIN_ATTEMPTS: usize = 64;

/// The part plan (`directParts`) for `ciphertext`: its parts, and each one's sha2-256.
fn direct_plan(ciphertext: &[u8]) -> (usize, Value) {
    use sha2::Digest as _;
    let part = if ciphertext.len() <= SINGLE_PART_MAX {
        ciphertext.len().max(1)
    } else {
        DIRECT_PART
    };
    let digests: Vec<String> = ciphertext
        .chunks(part)
        .map(|c| vti_common::blob_store::sha256_digest_multibase(&sha2::Sha256::digest(c).into()))
        .collect();
    (
        part,
        serde_json::json!({ "partSize": part, "partCount": digests.len(), "partDigests": digests }),
    )
}

/// `rooms file put` — seal a local file, upload its ciphertext, and write the record that
/// names it, all **as the member** (`rooms/blobs/*/0.2` through `rooms/keys/act`).
///
/// The file is sealed here under one file's key from the VTA (`rooms/keys/file-key`); its
/// bytes never pass through the VTA, and the host receives only ciphertext. The member's
/// VTA signs the begin, the record and — in direct mode — the commit, as the member; the
/// bytes go straight to the room's storage over targets the host issued (direct) or to the
/// host as chunk documents signed by a single-use upload key minted here for this upload
/// alone (proxied). This client's own key signs nothing the host receives.
pub async fn cmd_rooms_file_put(
    client: &VtaClient,
    target: RoomTarget<'_>,
    path: &std::path::Path,
    title: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    padme: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::rooms::blobs::upload;
    use vti_rooms::files::{self, FileBinding, Padding};

    let (sealed_tier, member) = room_tier(client, &target).await?;
    if !sealed_tier {
        return Err(
            "this room is `open`: its records are cleartext, and a file's manifest \
                    belongs inside a sealed body. Files go in `attributed` and `private` rooms."
                .into(),
        );
    }

    let plaintext = std::fs::read(path)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file has no usable name")?;
    // A fresh id for every file: the segment nonces are counters, so two files
    // under one key would reuse them.
    let file_id = files::new_file_id();
    let resp = client
        .room_file_key(target.room_id, &files::encode_file_id(&file_id), None)
        .await?;
    let file_key = file_key_bytes(&resp)?;
    let sealed = files::seal_file(
        &file_key,
        FileBinding {
            room_id: target.room_id.to_string(),
            file_id,
            epoch: resp.epoch.get(),
            segment_size: files::DEFAULT_SEGMENT_SIZE,
        },
        name,
        None,
        &plaintext,
        if padme { Padding::Padme } else { Padding::None },
    )?;
    let ciphertext: Vec<u8> = sealed.chunks.concat();

    // The upload key: minted here for this upload alone, from no key held for anything
    // else, and dropped when the upload ends.
    let (key_did, key_secret) = crate::local_keygen::generate_unbound_admin_did_key();
    let key_secret = zeroize::Zeroizing::new(key_secret);
    let (part_size, plan) = direct_plan(&ciphertext);
    let begin_payload = serde_json::json!({
        "roomId": target.room_id,
        "manifest": sealed.blob,
        "uploadKey": key_did,
        "directParts": plan,
    });
    let begin = || async {
        let (_, reply) = act_and_send(
            client,
            &target,
            upload::begin::v0_2::Payload::TYPE_URI,
            begin_payload.clone(),
        )
        .await?;
        parse_reply::<upload::begin::v0_2::Response>("rooms/blobs/upload/begin", reply)
    };
    let mut begun = begin().await?;
    let direct = wire_str(&begun.mode) == "direct";
    let upload_id = begun.upload_id.to_string();
    let host = target.client();

    let sent: Result<(), Box<dyn std::error::Error>> = async {
        if begun.already_committed == Some(true) {
            return Ok(());
        }
        if direct {
            // Each part to its own target, with exactly the headers it names; begin again,
            // with the identical manifest and plan, for parts beyond the first batch or
            // whose target lapsed.
            for _ in 0..DIRECT_BEGIN_ATTEMPTS {
                if begun.missing.is_empty() {
                    return Ok(());
                }
                if begun.targets.is_empty() {
                    return Err("the host answered direct mode with no targets".into());
                }
                for t in &begun.targets {
                    let i = usize::try_from(t.index)
                        .ok()
                        .filter(|i| i * part_size < ciphertext.len().max(1))
                        .ok_or("the host issued a target for a part that does not exist")?;
                    let part =
                        &ciphertext[i * part_size..((i + 1) * part_size).min(ciphertext.len())];
                    vtc_client::rooms::files::put_part(t, part).await?;
                }
                begun = begin().await?;
            }
            return Err("the upload did not finish: the host kept asking for parts".into());
        }
        for index in &begun.missing {
            let i = usize::try_from(index.0)
                .ok()
                .filter(|i| *i < sealed.chunks.len())
                .ok_or_else(|| {
                    format!("the host asked for chunk {}, which does not exist", index.0)
                })?;
            host.upload_chunk_v2(
                &upload_id,
                i as u64,
                &sealed.chunks[i],
                &key_did,
                &key_secret,
            )
            .await?;
        }
        Ok(())
    }
    .await;

    // Commit and abort: the upload key's (proxied), or the member's own (direct).
    let finish = |type_uri: &'static str| {
        let (upload_id, key_did, key_secret, member) = (
            upload_id.clone(),
            key_did.clone(),
            key_secret.clone(),
            member.clone(),
        );
        let target = &target;
        async move {
            let payload = serde_json::json!({ "uploadId": upload_id });
            if direct {
                act_and_send_as(client, target, type_uri, payload, Some(&member))
                    .await
                    .map(|(_, reply)| reply)
            } else {
                let doc = vta_sdk::trust_task_sign::build_signed(
                    type_uri,
                    payload,
                    &key_did,
                    &key_secret,
                    target.host_did.unwrap_or("did:key:zHost"),
                )
                .await
                .map_err(|e| format!("could not sign with the upload key: {e}"))?;
                let doc: Value = serde_json::from_str(&doc)?;
                Ok(target.client().send_signed_room_document(&doc).await?)
            }
        }
    };
    if let Err(e) = sent {
        // Release what `begin` reserved rather than leaving it to expire.
        let _ = finish(upload::abort::v0_2::Payload::TYPE_URI).await;
        return Err(e);
    }
    let committed: upload::commit::v0_2::Response = parse_reply(
        "rooms/blobs/upload/commit",
        finish(upload::commit::v0_2::Payload::TYPE_URI).await?,
    )?;
    let blob_ref = wire_str(&committed.blob_ref);
    if !files::same_digest(&blob_ref, &sealed.file.blob_ref) {
        return Err(format!(
            "the host committed {blob_ref}, not the blob sealed here ({})",
            sealed.file.blob_ref
        )
        .into());
    }

    let key = opaque_key();
    let mut content = SealedRecordBody::new(
        RecordLocation {
            room_id: target.room_id,
            key: &key,
            version: 1,
        },
        &member,
    );
    content.title = title;
    content.description = description;
    content.tags = tags;
    content.file = Some(sealed.file.clone());
    let version = write_sealed_naming(
        client,
        &target,
        content,
        Some(0),
        Some(vec![blob_ref.clone()]),
    )
    .await?;

    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({
            "key": key,
            "version": version,
            "blobRef": blob_ref,
            "size": sealed.file.size,
            "mode": if direct { "direct" } else { "proxied" },
        }))?;
        return Ok(());
    }
    println!(
        "Put {name} ({} bytes, {}) as record {key} at version {version}, as {member}\n  blobRef  {blob_ref}\n  Members fetch it with `pnm rooms file get {key}`.",
        sealed.file.size,
        if direct {
            "straight to the room's storage"
        } else {
            "through the host"
        }
    );
    Ok(())
}

/// A local file name from one another member chose: the last path component, without
/// leading dots, never empty.
fn local_name(untrusted: &str) -> String {
    let base = untrusted
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim_start_matches('.');
    let clean = inert(base).replace(['\n', '\t'], " ");
    if clean.trim().is_empty() {
        "room-file".to_string()
    } else {
        clean
    }
}

/// `rooms file get` — fetch a record's file **as the member**, check it against what its
/// author signed, and write the plaintext.
///
/// The record and the blob are asked for through the member's VTA (`rooms/keys/act`); the
/// bytes come straight from the room's storage when the host offers it (`direct`, a ranged
/// read per chunk), or chunk by chunk through the host, each request signed as the member.
/// Nothing is written unless every check holds: the record body's signature and location,
/// the blob being the one the author named, every chunk against the manifest, and the
/// plaintext against the author's digest.
pub async fn cmd_rooms_file_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::rooms::blobs::{chunk as blob_chunk, get as blob_get};
    use vti_rooms::files::{self, BlobManifest};

    let (member, record) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
        serde_json::json!({ "roomId": target.room_id, "key": key }),
    )
    .await?;
    let record: vtc_client::rooms::files::GetRecordV2Response =
        parse_reply("rooms/records/get", record)?;
    let sealed = record.sealed.as_ref().ok_or(
        "the record has no sealed body: it is on an `open` room, or it has been retracted",
    )?;
    let sealed = SealedContent {
        ciphertext: sealed.ciphertext.clone(),
        nonce: sealed.nonce.clone(),
        epoch: u32::try_from(sealed.epoch.get())
            .map_err(|_| "the record's epoch is beyond what this client can represent")?,
    };
    let verified = open_and_verify(
        client,
        &target,
        key,
        record.version.get(),
        &sealed,
        record.author.as_deref(),
    )
    .await?;
    let file = verified
        .body()
        .file
        .clone()
        .ok_or("the record carries no file")?;
    let named = record
        .blobs
        .iter()
        .flatten()
        .any(|b| files::same_digest(&wire_str(b), &file.blob_ref));
    if !named {
        return Err(
            "the host does not name the file's blob on this record; it may have been \
                    released"
                .into(),
        );
    }

    let (_, started) = act_and_send(
        client,
        &target,
        blob_get::v0_2::Payload::TYPE_URI,
        serde_json::json!({ "roomId": target.room_id, "blobRef": file.blob_ref, "direct": true }),
    )
    .await?;
    let started: blob_get::v0_2::Response = parse_reply("rooms/blobs/get", started)?;
    let blob: BlobManifest = serde_json::from_value(serde_json::to_value(&started.manifest)?)?;
    // The file manifest is the author's; the blob manifest is the host's. Before a byte is
    // trusted: it is the blob the author named, and its shape is the one the author's
    // segment size and length give.
    file.check_blob(&blob)?;
    let size = blob.size;
    let chunk_size = blob.chunks.chunk_size;
    let mut chunks = Vec::with_capacity(blob.chunks.chunk_digests.len());
    for (i, expected) in blob.chunks.chunk_digests.iter().enumerate() {
        let chunk = match (&started.target, &started.download_id) {
            (Some(t), _) => {
                let start = i as u64 * chunk_size;
                vtc_client::rooms::files::get_range(t, start..(start + chunk_size).min(size))
                    .await?
            }
            (None, Some(download_id)) => {
                let (_, reply) = act_and_send_as(
                    client,
                    &target,
                    blob_chunk::v0_1::Payload::TYPE_URI,
                    serde_json::json!({ "downloadId": download_id, "index": i }),
                    Some(&member),
                )
                .await?;
                let c: blob_chunk::v0_1::Response = parse_reply("rooms/blobs/chunk", reply)?;
                base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    c.data.as_str(),
                )?
            }
            (None, None) => {
                return Err("the host answered with neither a target nor a download".into());
            }
        };
        if !files::same_digest(&files::digest_multibase(&chunk), expected) {
            return Err(format!("chunk {i} does not match the manifest").into());
        }
        chunks.push(chunk);
    }

    let resp = client
        .room_file_key(target.room_id, &file.file_id, Some(file.epoch))
        .await
        .map_err(|e| file_key_refusal_hint(&e, &target))?;
    let file_key = file_key_bytes(&resp)?;
    let plaintext = files::open_file(&file_key, target.room_id, &file, &blob, &chunks)?;

    let out = match out {
        Some(p) => p.to_path_buf(),
        None => std::path::PathBuf::from(local_name(&file.name)),
    };
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    // Written beside the target and moved into place, so a failure leaves nothing that
    // looks like the file.
    let tmp = out.with_extension("partial");
    std::fs::write(&tmp, &plaintext)?;
    std::fs::rename(&tmp, &out)?;
    println!(
        "Fetched {} ({} bytes) into {}, written by {}; it matches the digest they signed.",
        inert(&file.name).escape_debug(),
        plaintext.len(),
        out.display(),
        verified.body().author
    );
    Ok(())
}

/// `rooms owner group-create` — found a sealed room's group in this VTA, with the owner
/// as its only member (`rooms/owner/group/create/0.1`).
pub async fn cmd_rooms_owner_group_create(
    client: &VtaClient,
    room_id: &str,
    signing_key_id: &str,
    member: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .room_group_create(room_id, signing_key_id, member)
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`noSigningKey` means this VTA will not let you name `{signing_key_id}` — \
                 check it with `pnm keys list --context <id>`. `alreadyExists` means it already \
                 holds this room's group, which is never replaced."
            )
        })?;
    println!("Founded the group of {room_id} at epoch {}.", resp.epoch);
    println!(
        "  Next: admit members with `pnm rooms owner invite` and `pnm rooms owner group-add`. \
         Writing needs your own membership and authority credentials in this VTA \
         (`pnm rooms owner issue-membership` / `issue-authority --store`), if not issued yet."
    );
    Ok(())
}

/// `rooms owner group-remove` — remove a member's leaf from a room's group
/// (`rooms/owner/group/remove/0.1`), advancing the room at its host.
pub async fn cmd_rooms_owner_group_remove(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    member: &str,
    reason: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Under one idempotency key, so a retry after a lost reply reports the removal that
    // happened instead of `notMember`.
    let resp = client
        .idempotent(|| client.room_group_remove(room_id, host_did, member, reason))
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`epochConflict` means another admin advanced the room: catch up and \
                 retry. `hostUnreachable` leaves the outcome unknown; running this again \
                 settles it with the host before anything else. `ownLeaf` means {member} is \
                 you: hand the room on with rooms/owner/transfer instead."
            )
        })?;
    println!(
        "Removed {member} from {room_id}; the room is now at epoch {}.",
        resp.epoch
    );
    println!(
        "  Nothing sealed from now on is readable to them. What they already read, and on a \
         `chained` room the epochs they were in, stay theirs. Their authority credential is \
         untouched: let it lapse, or issue none further."
    );
    Ok(())
}

/// `rooms owner group-renew` — renew a sealed room (`rooms/owner/group/renew/0.1`):
/// advance its group with a commit that changes no membership, and the room at its host
/// with that commit.
pub async fn cmd_rooms_owner_group_renew(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    reason: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Under one idempotency key, so a retry after a lost reply reports the renewal that
    // happened instead of renewing a second time.
    let resp = client
        .idempotent(|| client.room_group_renew(room_id, host_did, reason))
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`noGroup` means this VTA holds no group for {room_id}: an `open` room \
                 renews with `pnm rooms renew`. `epochConflict` means another admin advanced \
                 the room: catch up and retry. `hostUnreachable` leaves the outcome unknown; \
                 running this again settles it with the host before anything else."
            )
        })?;
    println!(
        "Renewed {room_id}; the room is now at epoch {}.",
        resp.epoch
    );
    println!(
        "  Nobody joined or left. Every remaining member's VTA must apply the commit before \
         it can write again: each runs `pnm rooms keys commit --room {room_id} --host <url> \
         --host-did {host_did}`."
    );
    Ok(())
}

/// `rooms owner group-add` — admit a member from their KeyPackage
/// (`rooms/owner/group/add/0.1`) and write the Welcome to `out` for delivery.
pub async fn cmd_rooms_owner_group_add(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    member: &str,
    key_package_src: &str,
    reason: Option<&str>,
    out: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    let key_package = if key_package_src == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(key_package_src)?
    };
    let key_package = key_package.trim().to_string();

    // Under one idempotency key: the answer is the only copy of the Welcome, and a
    // retry that re-executed would be refused `alreadyMember` with the Welcome lost.
    let resp = client
        .idempotent(|| client.room_group_add(room_id, host_did, member, &key_package, reason))
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`epochConflict` means another admin advanced the room: catch up and \
                 retry. `hostUnreachable` leaves the outcome unknown; running this again \
                 settles it with the host before anything else."
            )
        })?;

    let delivery = serde_json::json!({
        "roomId": room_id,
        "member": resp.member.as_str(),
        "epoch": resp.epoch,
        "welcome": resp.welcome.as_str(),
        "ratchetTree": resp.ratchet_tree.as_ref().map(|t| t.as_str()),
    });
    std::fs::write(out, serde_json::to_vec_pretty(&delivery)?)?;
    println!(
        "Admitted {member} to {room_id}; the room is now at epoch {}.",
        resp.epoch
    );
    println!(
        "  Deliver {} to the member's key holder (rooms/keys/welcome) directly — never \
         through the host.",
        out.display()
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

    fn vtc_target() -> RoomTarget<'static> {
        RoomTarget {
            host_url: "https://community.example/v1",
            host_did: Some("did:webvh:community.example"),
            room_id: "did:webvh:example.com:rooms:northwind",
        }
    }

    const CATCH_UP: &str = "pnm rooms keys commit --room did:webvh:example.com:rooms:northwind \
                            --host https://community.example/v1 --host-did did:webvh:community.example";

    /// A put sealed under a superseded epoch (`epochMismatch`, read off the host's
    /// `trust-task-error` document) names the catch-up command with the real values, not
    /// the raw HTTP body.
    #[test]
    fn a_superseded_epoch_put_prints_keys_commit_with_the_real_values() {
        let body = json!({
            "type": "https://trusttasks.org/spec/rooms/records/put/0.1#error",
            "payload": {
                "code": "rooms/records/put:epochMismatch",
                "message": "record is sealed under epoch 2, room `r` is at 3",
            },
        });
        let err: Box<dyn std::error::Error> = Box::new(vtc_client::VtcError::Http {
            status: 400,
            body: body.to_string(),
        });
        let text = put_refused(err, &vtc_target()).to_string();
        assert!(text.contains(CATCH_UP), "{text}");
        assert!(text.contains("sealed under epoch 2"), "{text}");
        assert!(!text.contains("HTTP 400"), "{text}");
    }

    /// Any other refusal passes through untouched, and no `--host-did` is invented for a
    /// host the operator named none for.
    #[test]
    fn other_put_refusals_pass_through_and_no_host_did_is_invented() {
        let t = vtc_target();
        assert!(put_refusal_hint("rooms/records/put:recordTooLarge", "", &t).is_none());
        let err: Box<dyn std::error::Error> = Box::new(vtc_client::VtcError::Http {
            status: 500,
            body: "not a document".into(),
        });
        assert_eq!(
            put_refused(err, &t).to_string(),
            "VTC returned HTTP 500: not a document"
        );

        let bare = RoomTarget {
            host_did: None,
            ..vtc_target()
        };
        assert_eq!(
            keys_commit_command(&bare),
            "pnm rooms keys commit --room did:webvh:example.com:rooms:northwind \
             --host https://community.example/v1"
        );
    }

    fn open_rejected(reason: &str, extra: Value) -> VtaError {
        let mut details = json!({ "reason": reason });
        details
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        VtaError::Rejected {
            code: "rooms/keys/open:unknownEpoch".into(),
            message: "record is sealed under epoch 4".into(),
            details: Some(details),
        }
    }

    /// A member removed from the group is told so, and is not sent to `keys commit`,
    /// which can never open what was sealed after the removal.
    #[test]
    fn a_removed_member_is_told_it_was_removed_not_to_catch_up() {
        let text = open_refusal_hint(
            &open_rejected("removed", json!({ "removedAtEpoch": 3 })),
            &vtc_target(),
        );
        assert!(
            text.contains("You were removed from this room's group at epoch 3"),
            "{text}"
        );
        assert!(!text.contains("keys commit"), "{text}");
    }

    fn file_key_rejected(reason: &str, message: &str) -> VtaError {
        VtaError::Rejected {
            code: "rooms/keys/file-key:unknownEpoch".into(),
            message: message.into(),
            details: Some(json!({ "reason": reason })),
        }
    }

    /// `pnm rooms file get` names the same remedies a record's refusal does. A removed
    /// member's file comes as `notDelivered` (`rooms/keys/file-key/0.1` declares no
    /// `removed`), with the VTA's message saying so — and the hint tells the operator that
    /// catching up will not help then.
    #[test]
    fn a_file_key_refusal_names_the_remedy() {
        let removed = file_key_rejected(
            "notDelivered",
            "the file is sealed under epoch 4, and this member was removed from room `r`'s \
             group at epoch 3: no commit will make its key derivable here",
        );
        let text = file_key_refusal_hint(&removed, &vtc_target());
        assert!(text.contains("was removed from room"), "{text}");
        assert!(text.contains(CATCH_UP), "{text}");
        assert!(text.contains("catching up will not help"), "{text}");
        assert!(text.contains("files sealed since your removal"), "{text}");

        let behind = file_key_refusal_hint(
            &file_key_rejected("beyondChain", "sealed under epoch 1"),
            &vtc_target(),
        );
        assert!(behind.contains("pnm rooms keys backfill"), "{behind}");
        assert!(behind.contains("The file is older"), "{behind}");

        // An `open` code is not a file-key one: the reason is not read across tasks.
        let wrong_task = VtaError::Rejected {
            code: "rooms/keys/open:unknownEpoch".into(),
            message: "x".into(),
            details: Some(json!({ "reason": "beyondChain" })),
        };
        assert!(
            file_key_refusal_hint(&wrong_task, &vtc_target()).contains("did not open with any key")
        );
    }

    /// A member who is only behind gets the catch-up command with the real values.
    #[test]
    fn a_member_behind_is_told_to_catch_up() {
        let text = open_refusal_hint(
            &open_rejected("notDelivered", json!({ "heldEpoch": 2 })),
            &vtc_target(),
        );
        assert!(text.contains(CATCH_UP), "{text}");
    }

    /// `pnm rooms renew` refuses a sealed room and names the command that renews it
    /// (rooms/keys/act/0.1 producer item 4); an open room renews as before.
    #[test]
    fn renew_refuses_a_sealed_room_and_names_group_renew() {
        let target = RoomTarget {
            host_url: "https://community.example/v1",
            host_did: Some("did:webvh:community.example"),
            room_id: "did:webvh:example.com:rooms:northwind",
        };
        assert!(refuse_sealed_renew("open", &target).is_ok());
        for tier in ["attributed", "private"] {
            let e = refuse_sealed_renew(tier, &target).expect_err(tier);
            assert!(
                e.contains(
                    "pnm rooms owner group-renew --room did:webvh:example.com:rooms:northwind \
                     --host-did did:webvh:community.example"
                ),
                "{e}"
            );
            assert!(e.contains(tier), "{e}");
        }
        let no_did = RoomTarget {
            host_did: None,
            ..target
        };
        let e = refuse_sealed_renew("private", &no_did).unwrap_err();
        assert!(e.contains("--host-did <the host's DID>"), "{e}");
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

    /// Another member's text reaches a terminal: an escape sequence in it must not.
    #[test]
    fn untrusted_text_loses_its_control_characters_but_keeps_its_lines() {
        assert_eq!(inert("a\x1b[2Jb\nc\td\x07"), "a[2Jb\nc\td");
    }

    /// A file name chosen by another member must not choose where it is written.
    #[test]
    fn a_file_name_cannot_leave_the_directory_or_hide() {
        assert_eq!(local_name("../../etc/passwd"), "passwd");
        assert_eq!(local_name("C:\\Users\\x\\evil.exe"), "evil.exe");
        assert_eq!(local_name(".bashrc"), "bashrc");
        assert_eq!(local_name("term sheet.pdf"), "term sheet.pdf");
        assert_eq!(local_name("../"), "room-file");
        assert_eq!(local_name("a\nb.txt"), "a b.txt");
    }

    /// Record keys on a sealed tier say nothing, and do not repeat.
    #[test]
    fn opaque_keys_are_fresh_and_uninformative() {
        let (a, b) = (opaque_key(), opaque_key());
        assert_ne!(a, b);
        assert_eq!(a.len(), 22, "16 random bytes, base64url");
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
