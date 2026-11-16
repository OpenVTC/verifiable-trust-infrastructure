//! Room files: sealing and opening locally, and the put and get transfers, plus
//! the sealed-record writes they share.

use super::*;

// ─── Files ───────────────────────────────────────────────────────────────
//
// Sealing and opening a room file locally, with one file's key from the VTA
// (`rooms/keys/file-key/0.2`). The bytes never pass through the VTA; what the
// VTA releases opens this one file and nothing else.
//
// What is written is the upload's whole input and nothing more: the sealed
// chunks, the blob manifest a host checks, and the file manifest that belongs
// inside the sealed record body. Uploading them is `rooms/blobs/upload/*` and
// a record put naming the blob.

/// The blob manifest beside the chunks.
pub(super) const BLOB_MANIFEST: &str = "blob.json";

/// The file manifest — the sealed record body's `file` member.
pub(super) const FILE_MANIFEST: &str = "file.json";

/// The sealed chunks, in index order.
pub(super) const CHUNKS_DIR: &str = "chunks";

pub(super) fn chunk_path(dir: &std::path::Path, index: usize) -> std::path::PathBuf {
    dir.join(CHUNKS_DIR).join(format!("{index:06}.bin"))
}

#[allow(deprecated)] // file-key 0.2 is still served, and this names no purpose of use
pub(super) fn file_key_bytes(
    resp: &vti_specs::rooms::keys::file_key::v0_2::Response,
) -> Result<vti_rooms::files::FileKey, Box<dyn std::error::Error>> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(resp.key.as_str())?;
    bytes
        .try_into()
        .map_err(|_| "the VTA returned a file key that is not 32 bytes".into())
}

/// `rooms file seal` — seal a local file for a room, ready to upload.
#[allow(deprecated)] // file-key 0.2 is still served, and sealing names no purpose of use
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
pub(super) const SEALED_WRITE_ATTEMPTS: usize = 4;

/// Whether the room seals its records, from `rooms/info` read as the member — and which
/// member the VTA acted as, which is the author a sealed body names.
pub(super) async fn room_tier(
    client: &VtaClient,
    target: &RoomTarget<'_>,
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let (sealed, member, _) = room_tier_and_epoch(client, target).await?;
    Ok((sealed, member))
}

/// [`room_tier`], and the room's current epoch — the one an open room's file is written
/// at (`rooms/records/put/0.4` Producer item 7).
#[allow(deprecated)] // info/0.3 is the version rooms/keys/act's table carries
pub(super) async fn room_tier_and_epoch(
    client: &VtaClient,
    target: &RoomTarget<'_>,
) -> Result<(bool, String, u64), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    let (member, reply) = act_and_send(
        client,
        target,
        vti_specs::rooms::info::v0_3::Payload::TYPE_URI,
        serde_json::json!({ "roomId": target.room_id }),
    )
    .await
    .map_err(|e| format!("could not read the room's tier (rooms/info): {e}"))?;
    let visibility = reply
        .get("visibility")
        .and_then(Value::as_str)
        .ok_or("the host's rooms/info response names no visibility")?;
    let epoch = reply
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or("the host's rooms/info response names no epoch")?;
    Ok((visibility != "open", member, epoch))
}

/// Have the VTA sign `content` **as the member** and seal it (`rooms/keys/seal/0.2`), and
/// put it as the member (`rooms/keys/act/0.10`), re-sealing at the version the host assigned
/// whenever that is not the one sealed for. Returns the version written.
///
/// The record's associated data and its signed body both name the version, and the host
/// assigns it from a room-wide counter, so the version is predicted from the room's head and
/// a miss is corrected by a rewrite. Until that rewrite lands the record does not open,
/// which is why a write that runs out of attempts says so and names the key.
pub(super) async fn write_sealed(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    content: SealedRecordBody,
    expected_version: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>> {
    write_sealed_naming(client, target, content, expected_version, None).await
}

/// [`write_sealed`], naming `blobs` committed in the room (`rooms/records/put/0.2`).
#[allow(deprecated)] // act/0.10, seal/0.2 and get/0.2 are what this CLI sends until it moves (trust-tasks-tf #1027)
pub(super) async fn write_sealed_naming(
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
    let mut content = content;
    for _ in 0..SEALED_WRITE_ATTEMPTS {
        // Unsigned: the VTA signs it as its author, the member, before sealing.
        // seal/0.3 where the VTA serves it, which a body carrying the governed members needs.
        let unsigned = serde_json::to_vec(&content.clone().at_version(intended))?;
        let sealed = match client
            .room_seal_as_principal_v0_3(target.room_id, &key, intended, &unsigned)
            .await
        {
            Ok(r) => serde_json::to_value(r.sealed)?,
            // A VTA that predates seal/0.3 seals only bodies without them. A `writtenAt`
            // added because the profile permits it is dropped rather than refusing the
            // write; one the operator asked for is not.
            Err(VtaError::UnsupportedTaskType { .. })
                if content.written_at.is_some()
                    && content.kind.is_none()
                    && content.in_reply_to.is_none()
                    && content.edited_at.is_none() =>
            {
                content.written_at = None;
                continue;
            }
            Err(e @ VtaError::UnsupportedTaskType { .. }) => {
                return Err(format!(
                    "{e}\n\nYour VTA predates `rooms/keys/seal/0.3`, which seals a body \
                     carrying --kind or --reply-to: upgrade it, or write the record without \
                     them."
                )
                .into());
            }
            Err(e) => return Err(e.into()),
        };
        let mut payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "sealed": {
                "ciphertext": sealed["ciphertext"],
                "nonce": sealed["nonce"],
                "epoch": sealed["epoch"],
            },
        });
        if let Some(v) = expected {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        if let Some(b) = &blobs {
            payload["blobs"] = serde_json::json!(b);
        }
        // put/0.5 where the VTA and host serve it, else put/0.3: on a sealed tier the host
        // sees ciphertext either way. A record naming blobs keeps to put/0.3, whose blob
        // handling every host serves.
        let (_, reply) = if blobs.is_some() {
            act_and_send(
                client,
                target,
                vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
                payload,
            )
            .await
            .map_err(|e| put_refused(e, target))?
        } else {
            let (principal, reply, _) = act_and_send_newest(
                client,
                target,
                (vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE, payload.clone()),
                Some((vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE, payload)),
            )
            .await
            .map_err(|e| put_refused(e, target))?;
            (principal, reply)
        };
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
pub(super) fn keys_commit_command(target: &RoomTarget<'_>) -> String {
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
pub(super) fn put_refused(
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
pub(super) fn put_refusal_hint(
    code: &str,
    message: &str,
    target: &RoomTarget<'_>,
) -> Option<String> {
    use vti_specs::rooms::records::put;
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
pub(super) fn open_refusal_hint(e: &VtaError, target: &RoomTarget<'_>) -> String {
    use vti_specs::rooms::keys::open::v0_2::error_codes::UNKNOWN_EPOCH;
    epoch_refusal_hint(e, target, UNKNOWN_EPOCH.code, Sealed::Record)
}

/// The operator-facing text for a `rooms/keys/file-key` refusal, as `pnm rooms file
/// get` and `file open` print it — the same remedies a record's refusal names.
pub(super) fn file_key_refusal_hint(e: &VtaError, target: &RoomTarget<'_>) -> String {
    use vti_specs::rooms::keys::file_key::v0_2::error_codes::UNKNOWN_EPOCH;
    epoch_refusal_hint(e, target, UNKNOWN_EPOCH.code, Sealed::File)
}

/// What a refused epoch had sealed, for the wording of [`epoch_refusal_hint`].
#[derive(Clone, Copy)]
pub(super) enum Sealed {
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
/// `notDelivered` (catch up), `beyondChain` (backfill) and `removed` (no commit will
/// help: `rooms/keys/{open,file-key}/0.2` say a caller MUST NOT retry after catching up)
/// — never by the message. The text checks are only for a refusal that carries no reason.
pub(super) fn epoch_refusal_hint(
    e: &VtaError,
    target: &RoomTarget<'_>,
    code: &str,
    sealed: Sealed,
) -> String {
    let noun = sealed.noun();
    let text = e.to_string();
    let reason = (e.rejection_code() == Some(code))
        .then(|| e.rejection_details())
        .flatten()
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str);
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
             Catch up, then try again:\n\n  {}",
            keys_commit_command(target),
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

/// Open a sealed record through the VTA and check its body before anything in it is used.
///
/// `version` is the record's; the body is opened, and its signed location checked, at the
/// version it was **sealed** at — `sealed.version` where the host served one, because a
/// curation moves a record past its body. A record curated by a host that predates that
/// member carries none, and the VTA searches earlier versions and says which opened.
pub(super) async fn open_and_verify(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    key: &str,
    version: u64,
    sealed: &SealedContent,
    host_author: Option<&str>,
) -> Result<VerifiedRecordBody, Box<dyn std::error::Error>> {
    let sealed_at = sealed
        .sealed_at(version)
        .map_err(|why| format!("refusing record {key}: the host says {why}"))?;
    let opened = client
        .room_open(
            target.room_id,
            key,
            sealed_at,
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
    // Where the VTA found it sealed, if not where it was asked to look.
    let opened_at = opened
        .pointer("/ext/org.openvtc.rooms/sealedAt")
        .and_then(Value::as_u64)
        .unwrap_or(sealed_at);
    if opened_at > sealed_at {
        return Err(format!(
            "refusing record {key}: the VTA opened it at version {opened_at}, past the {sealed_at} it was asked for"
        )
        .into());
    }
    let location = RecordLocation {
        room_id: target.room_id,
        key,
        version: opened_at,
    };
    Ok(verify_record_body(&bytes, location, host_author, &resolver)
        .await
        .map_err(|e| format!("refusing record {key}: {e}"))?)
}

/// The part size a direct upload is cut into: one part up to [`SINGLE_PART_MAX`], else
/// parts of this size (storage's multipart floor is 5 MiB).
pub(super) const DIRECT_PART: usize = 8 * 1024 * 1024;

/// The largest blob sent as one direct part.
pub(super) const SINGLE_PART_MAX: usize = 16 * 1024 * 1024;

/// How many times a direct upload asks again for targets before giving up.
pub(super) const DIRECT_BEGIN_ATTEMPTS: usize = 64;

/// The part plan (`directParts`) for `ciphertext`: its parts, and each one's sha2-256.
pub(super) fn direct_plan(ciphertext: &[u8]) -> (usize, Value) {
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
/// On a sealed room the file is sealed here under one file's key from the VTA
/// (`rooms/keys/file-key`), and its manifest goes inside the sealed body. On an `open` room
/// the key is minted here at random and the manifest, key included, goes in the record's
/// cleartext (`rooms/records/put/0.4`): the host and every member can open it, and the
/// storage holds only ciphertext. Either way its bytes never pass through the VTA. The member's
/// VTA signs the begin, the record and — in direct mode — the commit, as the member; the
/// bytes go straight to the room's storage over targets the host issued (direct) or to the
/// host as chunk documents signed by a single-use upload key minted here for this upload
/// alone (proxied). This client's own key signs nothing the host receives.
#[allow(deprecated)] // file-key 0.2 is still served, and this names no purpose of use
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
    use vti_rooms::files::{self, FileBinding, Padding};
    use vti_specs::rooms::blobs::upload;

    let (sealed_tier, member, room_epoch) = room_tier_and_epoch(client, &target).await?;

    let plaintext = std::fs::read(path)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file has no usable name")?;
    // A fresh id for every file: the segment nonces are counters, so two files
    // under one key would reuse them.
    let file_id = files::new_file_id();
    // A sealed room's file key is derived from its storage key, by the VTA. An open room
    // has none: the key is minted here for this file alone, and the record carries it in
    // the clear (`rooms/records/put/0.4` Producer item 7).
    let (file_key, epoch) = if sealed_tier {
        let resp = client
            .room_file_key(target.room_id, &files::encode_file_id(&file_id), None)
            .await?;
        (file_key_bytes(&resp)?, resp.epoch.get())
    } else {
        (files::new_file_key(), room_epoch)
    };
    let mut sealed = files::seal_file(
        &file_key,
        FileBinding {
            room_id: target.room_id.to_string(),
            file_id,
            epoch,
            segment_size: files::DEFAULT_SEGMENT_SIZE,
        },
        name,
        None,
        &plaintext,
        if padme { Padding::Padme } else { Padding::None },
    )?;
    if !sealed_tier {
        sealed.file.file_key = Some(files::encode_file_key(&file_key));
    }
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
    let version = if sealed_tier {
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
        write_sealed_naming(
            client,
            &target,
            content,
            Some(0),
            Some(vec![blob_ref.clone()]),
        )
        .await?
    } else {
        // In the clear, the manifest and its key included: on an open room the host and
        // every member read the record, so they open the file too.
        let mut cleartext = serde_json::to_value(CleartextContent {
            title,
            description,
            tags,
            ..Default::default()
        })?;
        cleartext["file"] = serde_json::to_value(&sealed.file)?;
        let (_, reply) = act_and_send(
            client,
            &target,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V4_TYPE,
            serde_json::json!({
                "roomId": target.room_id,
                "key": key,
                "cleartext": cleartext,
                "expectedVersion": 0,
                "blobs": [blob_ref],
            }),
        )
        .await
        .map_err(|e| put_refused(e, &target))?;
        parse_reply::<vti_rooms::wire::PutRecordResponse>("rooms/records/put", reply)?.version
    };
    keep_name_near_head(client, &target, version).await;

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
pub(super) fn local_name(untrusted: &str) -> String {
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
#[allow(deprecated)] // act/0.10, seal/0.2 and get/0.2 are what this CLI sends until it moves (trust-tasks-tf #1027)
pub async fn cmd_rooms_file_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    use vti_rooms::files::{self, BlobManifest};
    use vti_specs::rooms::blobs::{chunk as blob_chunk, get as blob_get};

    let (member, record) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
        serde_json::json!({ "roomId": target.room_id, "key": key }),
    )
    .await?;
    let record: vtc_client::rooms::files::GetRecordV2Response =
        parse_reply("rooms/records/get", record)?;
    // An open room's record describes its file in the clear, key included
    // (`rooms/records/put/0.4`); a sealed room's, inside the body its author signed.
    let (file, author, carried) = match record.cleartext.get("file") {
        Some(file) if record.sealed.is_none() => {
            let file: files::FileManifest = serde_json::from_value(file.clone())
                .map_err(|e| format!("the record's file manifest does not read: {e}"))?;
            let key = file
                .carried_key(true)?
                .ok_or("an open room's file manifest carries no key")?;
            let author = record
                .author
                .clone()
                .unwrap_or_else(|| "an unnamed member".to_string());
            (file, author, Some(key))
        }
        _ => {
            let sealed = record.sealed.as_ref().ok_or(
                "the record carries no file: it has neither a sealed body nor a `cleartext.file`, \
                 or it has been retracted",
            )?;
            let sealed = SealedContent {
                ciphertext: sealed.ciphertext.clone(),
                nonce: sealed.nonce.clone(),
                epoch: u32::try_from(sealed.epoch.get())
                    .map_err(|_| "the record's epoch is beyond what this client can represent")?,
                // The version the body was sealed at, where a curation moved the record past it
                // (rooms `_shared/0.1` `SealedRecord.version`): opened and verified there, and a
                // `sealed.version` above the record's own refused by `open_and_verify`.
                version: sealed.version.map(std::num::NonZeroU64::get),
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
            // A sealed room's key is derived; a manifest carrying one is refused.
            file.carried_key(false)?;
            (file, verified.body().author.clone(), None)
        }
    };
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

    let file_key = match carried {
        Some(key) => key,
        None => {
            let resp = client
                .room_file_key(target.room_id, &file.file_id, Some(file.epoch))
                .await
                .map_err(|e| file_key_refusal_hint(&e, &target))?;
            file_key_bytes(&resp)?
        }
    };
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
        "Fetched {} ({} bytes) into {}, written by {}; it matches the digest {}.",
        inert(&file.name).escape_debug(),
        plaintext.len(),
        out.display(),
        inert(&author),
        if carried.is_some() {
            "its record states (an open room's record is not signed by its author)"
        } else {
            "they signed"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::test_support::*;
    use serde_json::json;

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

    /// `pnm rooms file get` names the same remedies a record's refusal does. A removed
    /// member's file comes as `removed` (`rooms/keys/file-key/0.2`), and the operator is
    /// told so and not sent to `keys commit` — the caller MUST NOT retry after catching up.
    #[test]
    fn a_file_key_refusal_names_the_remedy() {
        let removed = VtaError::Rejected {
            code: "rooms/keys/file-key:unknownEpoch".into(),
            message: "the file is sealed under epoch 4, and this member was removed".into(),
            details: Some(json!({ "reason": "removed", "removedAtEpoch": 3 })),
        };
        let text = file_key_refusal_hint(&removed, &vtc_target());
        assert!(
            text.contains("You were removed from this room's group at epoch 3"),
            "{text}"
        );
        assert!(text.contains("Files sealed since then"), "{text}");
        assert!(!text.contains("keys commit"), "{text}");

        // Only behind: catch up.
        let behind_commit = file_key_refusal_hint(
            &file_key_rejected("notDelivered", "the file is sealed under epoch 4"),
            &vtc_target(),
        );
        assert!(behind_commit.contains(CATCH_UP), "{behind_commit}");

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
}
