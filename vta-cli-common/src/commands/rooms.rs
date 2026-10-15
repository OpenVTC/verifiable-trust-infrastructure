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
//! nowhere. File transfer and `renew` still present for this client
//! ([`VtaClient::room_present`]) and sign with its own key; they move separately.
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
    let host_did = target.host_did.unwrap_or("did:key:zHost");
    let document = vta_sdk::client::unsigned_room_request(type_uri, host_did, None, payload)?;
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

/// Whether the room seals its records, from `rooms/info`, presented for this client — the
/// file commands' path until their transfer moves to acting as the member.
async fn is_sealed_tier(
    target: &RoomTarget<'_>,
    signer: &RoomSigner<'_>,
    read: &RoomSession,
) -> Result<bool, Box<dyn std::error::Error>> {
    let info = target
        .client()
        .room_info(read, signer.did, signer.key_multibase)
        .await
        .map_err(|e| format!("could not read the room's tier (rooms/info): {e}"))?;
    Ok(wire_str(&info.visibility) != "open")
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
        let (_, reply) = act_and_send(
            client,
            target,
            vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
            payload,
        )
        .await?;
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

/// Sign `content`, seal it through the VTA and put it, re-sealing at the version the host
/// assigned whenever that is not the one sealed for. Returns the version written.
///
/// The record's associated data and its signed body both name the version, and the host
/// assigns it from a room-wide counter, so the version is predicted from the room's head and
/// a miss is corrected by a rewrite. Until that rewrite lands the record does not open,
/// which is why a write that runs out of attempts says so and names the key.
#[allow(clippy::too_many_arguments)]
async fn write_sealed_as_client(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    signer: &RoomSigner<'_>,
    read: &RoomSession,
    write: &RoomSession,
    content: SealedRecordBody,
    blobs: Option<Vec<String>>,
    expected_version: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let holder =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(signer.did, signer.key_multibase)?;
    let host = target.client();
    let head = host
        .list_records(read, None, None, None, signer.did, signer.key_multibase)
        .await?
        .head_version
        .unwrap_or(0);

    let key = content.key.clone();
    let mut intended = head + 1;
    let mut expected = expected_version;
    let mut landed = 0;
    for _ in 0..SEALED_WRITE_ATTEMPTS {
        let signed = content.clone().at_version(intended).sign(&holder).await?;
        let sealed = client
            .room_seal(target.room_id, &key, intended, &signed)
            .await?
            .sealed;
        let sealed = SealedContent {
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce,
            epoch: u32::try_from(sealed.epoch.get())
                .map_err(|_| "the VTA sealed under an epoch this client cannot represent")?,
        };
        landed = match &blobs {
            Some(blobs) => host
                .put_sealed_record_with_blobs(
                    write,
                    &key,
                    sealed,
                    blobs,
                    expected,
                    signer.did,
                    signer.key_multibase,
                )
                .await?
                .version
                .get(),
            None => {
                host.put_record(
                    write,
                    &key,
                    Some(sealed),
                    None,
                    expected,
                    signer.did,
                    signer.key_multibase,
                )
                .await?
                .version
            }
        };
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
        .map_err(|e| {
            // The failures operators will actually hit, named where they will read
            // them. Each reads like corruption if nobody says otherwise, and the two
            // epoch cases have opposite remedies.
            let text = e.to_string();
            let hint = if text.contains("cannot reach") {
                "The record is older than any key this VTA holds — it was written before \
                 you joined. Fetch the room's history: `pnm rooms keys backfill --room \
                 <room> --host-did <host>`."
            } else if text.contains("has not been delivered") {
                "The record is newer than this VTA's group. Catch up with `pnm rooms keys \
                 commit --room <room> --host <url> --host-did <host>`; if that says you were \
                 removed, nothing sealed after your removal will open."
            } else {
                "The record did not open with any key this VTA holds."
            };
            format!("{e}\n\n{hint}")
        })?;
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

/// `rooms file put` — seal a local file, upload its ciphertext, and write the record that
/// names it.
///
/// The file is sealed here under one file's key from the VTA (`rooms/keys/file-key`); its
/// bytes never pass through the VTA, and the host receives only ciphertext. Its name, type,
/// size and plaintext digest go inside the record's signed, sealed body.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_rooms_file_put(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    path: &std::path::Path,
    title: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    padme: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::files::{self, FileBinding, Padding};

    let read = present(client, &target, "read").await?;
    if !is_sealed_tier(&target, &signer, &read).await? {
        return Err(
            "this room is `open`: its records are cleartext, and a file's manifest \
                    belongs inside a sealed body. Files go in `attributed` and `private` rooms."
                .into(),
        );
    }
    let write = present(client, &target, "write").await?;

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

    let host = target.client();
    let begun = host
        .begin_upload(&write, &sealed.blob, signer.did, signer.key_multibase)
        .await?;
    let blob_ref = if begun.already_committed == Some(true) {
        sealed.file.blob_ref.clone()
    } else {
        let upload_id = wire_str(&begun.upload_id);
        let sent: Result<(), Box<dyn std::error::Error>> = async {
            for index in &begun.missing {
                let i = usize::try_from(index.0)
                    .ok()
                    .filter(|i| *i < sealed.chunks.len())
                    .ok_or_else(|| {
                        format!("the host asked for chunk {}, which does not exist", index.0)
                    })?;
                host.upload_chunk(
                    &upload_id,
                    i as u64,
                    &sealed.chunks[i],
                    signer.did,
                    signer.key_multibase,
                )
                .await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = sent {
            // Release what `begin` reserved rather than leaving it to expire.
            let _ = host
                .abort_upload(&upload_id, signer.did, signer.key_multibase)
                .await;
            return Err(e);
        }
        let committed = host
            .commit_upload(&upload_id, signer.did, signer.key_multibase)
            .await?;
        wire_str(&committed.blob_ref)
    };
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
        signer.did,
    );
    content.title = title;
    content.description = description;
    content.tags = tags;
    content.file = Some(sealed.file.clone());
    let version = write_sealed_as_client(
        client,
        &target,
        &signer,
        &read,
        &write,
        content,
        Some(vec![blob_ref.clone()]),
        Some(0),
    )
    .await?;

    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({
            "key": key,
            "version": version,
            "blobRef": blob_ref,
            "size": sealed.file.size,
        }))?;
        return Ok(());
    }
    println!(
        "Put {name} ({} bytes) as record {key} at version {version}\n  blobRef  {blob_ref}\n  Members fetch it with `pnm rooms file get {key}`.",
        sealed.file.size
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

/// `rooms file get` — fetch a record's file, check it against what its author signed, and
/// write the plaintext.
///
/// Nothing is written unless every check holds: the record body's signature and location,
/// the blob being the one the author named, every chunk against the manifest, and the
/// plaintext against the author's digest.
pub async fn cmd_rooms_file_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    key: &str,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::files::{self, BlobManifest};

    let read = present(client, &target, "read").await?;
    let host = target.client();
    let record = host
        .get_record_v2(&read, key, signer.did, signer.key_multibase)
        .await?;
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

    let started = host
        .get_blob(&read, &file.blob_ref, signer.did, signer.key_multibase)
        .await?;
    let blob: BlobManifest = serde_json::from_value(serde_json::to_value(&started.manifest)?)?;
    // The file manifest is the author's; the blob manifest is the host's. Before a byte is
    // trusted: it is the blob the author named, and its shape is the one the author's
    // segment size and length give.
    file.check_blob(&blob)?;
    let download_id = wire_str(&started.download_id);
    let mut chunks = Vec::with_capacity(blob.chunks.chunk_digests.len());
    for (i, expected) in blob.chunks.chunk_digests.iter().enumerate() {
        let chunk = host
            .download_chunk(&download_id, i as u64, signer.did, signer.key_multibase)
            .await?;
        if !files::same_digest(&files::digest_multibase(&chunk), expected) {
            return Err(format!("chunk {i} does not match the manifest").into());
        }
        chunks.push(chunk);
    }

    let resp = client
        .room_file_key(target.room_id, &file.file_id, Some(file.epoch))
        .await?;
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
