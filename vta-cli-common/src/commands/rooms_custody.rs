//! `pnm rooms owner {register,invite,issue-membership,issue-authority}` and
//! `pnm rooms keys …` — the room's credentials and the joiner's key holder.
//!
//! Every verb here is a call to the operator's own VTA, which holds the keys:
//! the room's signing key for the owner's verbs, the member's MLS group for the
//! key holder's. Nothing secret reaches this process. The only verb that also
//! talks to a host is `rooms keys commit --host`, which fetches the commits the
//! VTA missed from the host's relay and hands them to the VTA in order.
//!
//! # Every party here is a persona DID
//!
//! The owner, a member, the subject of a credential: each is a DID the
//! person's VTA holds for them in one of their contexts (typically a
//! `did:webvh` minted there), never the key this CLI authenticates with. So
//! none of these verbs defaults a party to the session's DID.

use std::io::Write as _;
use std::num::NonZeroU64;
use std::path::Path;

use chrono::{DateTime, Utc};
use vta_sdk::client::{RoomAction, RoomRegistration, VtaClient};

use super::rooms::RoomTarget;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// What every error naming a party should end with: where a persona DID comes from.
const PERSONA_HINT: &str = "Room parties are persona DIDs — DIDs your VTA holds for you in \
     one of your contexts (`pnm did-mgmt dids list`), never the key this CLI signs in with.";

/// Read a text argument that is a file path, or `-` for stdin. Trimmed.
fn read_text(src: &str, what: &str) -> Result<String, Box<dyn std::error::Error>> {
    let text = if src == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(src).map_err(|e| format!("read the {what} from {src}: {e}"))?
    };
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err(format!("the {what} in {src} is empty").into());
    }
    Ok(text)
}

/// Write `contents` to a new file, refusing to replace one that exists.
///
/// Created exclusively rather than checked-then-written, so a file that appears
/// between the two is not overwritten either.
fn write_new(path: &Path, contents: &[u8]) -> CmdResult {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                format!(
                    "{} already exists; refusing to overwrite it",
                    path.display()
                )
            }
            _ => format!("create {}: {e}", path.display()),
        })?;
    f.write_all(contents)?;
    Ok(())
}

/// Resolve `--valid-until <RFC 3339>` / `--valid-for <duration>` into an instant.
///
/// At most one is given (clap enforces it); neither is `None`, and the caller
/// decides whether that is allowed.
pub fn validity(
    valid_until: Option<&str>,
    valid_for: Option<&str>,
) -> Result<Option<DateTime<Utc>>, Box<dyn std::error::Error>> {
    match (valid_until, valid_for) {
        (Some(_), Some(_)) => Err("give --valid-until or --valid-for, not both".into()),
        (Some(t), None) => {
            let at = DateTime::parse_from_rfc3339(t)
                .map_err(|e| {
                    format!(
                        "--valid-until `{t}` is not an RFC 3339 time (2027-01-01T00:00:00Z): {e}"
                    )
                })?
                .with_timezone(&Utc);
            if at <= Utc::now() {
                return Err(format!("--valid-until `{t}` is already in the past").into());
            }
            Ok(Some(at))
        }
        (None, Some(d)) => {
            let secs = crate::duration::parse_duration_secs(d)?;
            let secs = i64::try_from(secs).map_err(|_| format!("--valid-for `{d}` is too long"))?;
            Ok(Some(
                Utc::now()
                    + chrono::Duration::try_seconds(secs)
                        .ok_or_else(|| format!("--valid-for `{d}` is too long"))?,
            ))
        }
        (None, None) => Ok(None),
    }
}

/// Parse `--action` values into the generated action type. Empty is refused: a
/// grant of nothing and a grant of everything are the two readings of it.
pub fn parse_actions(actions: &[String]) -> Result<Vec<RoomAction>, Box<dyn std::error::Error>> {
    if actions.is_empty() {
        return Err("name at least one --action: read, write, curate or admin".into());
    }
    actions
        .iter()
        .map(|a| {
            a.parse::<RoomAction>().map_err(|_| {
                format!("`{a}` is not a room action; use read, write, curate or admin").into()
            })
        })
        .collect()
}

// ─── Owner ───────────────────────────────────────────────────────────────

/// `rooms owner register` — have this VTA register the room with its host
/// (`rooms/owner/register/0.2`, falling back to 0.1 on a VTA that does not serve it),
/// signing `rooms/create` as `owner`, and say plainly when the room's revocation list is
/// not in force there.
pub async fn cmd_rooms_owner_register(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    owner: &str,
    visibility: &str,
    retention_days: Option<u64>,
    retention_policy: Option<&str>,
) -> CmdResult {
    let visibility = visibility
        .parse()
        .map_err(|_| "--visibility must be one of: open, attributed, private")?;
    let retention_days = match retention_days {
        Some(d) => Some(NonZeroU64::new(d).ok_or("--retention-days must be at least 1")?),
        None => None,
    };
    let retention_policy = match retention_policy {
        Some(p) => Some(
            p.parse()
                .map_err(|_| "--retention-policy must be `chained` or `fromJoin`")?,
        ),
        None => None,
    };

    let resp = client
        .room_owner_register(RoomRegistration {
            room_id,
            host_did,
            visibility,
            owner_did: Some(owner),
            retention_days,
            retention_policy,
        })
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`permissionDenied` means this VTA holds no signing key for `{owner}` in \
                 a context you act in. {PERSONA_HINT} On a community (VTC) host the owner must \
                 also be a member there: `not-a-member` means it is not, and \
                 `private-tier-not-enabled` that the community has not turned that tier on."
            )
        })?;
    println!(
        "Registered {} with {} as {owner}; the room is at epoch {}.",
        resp.room_id, resp.host, resp.epoch
    );
    // `rooms/owner/register/0.2`: anything but `inForce` is a room its host serves without
    // its withdrawals, and the person who asked has to be told so rather than shown a room
    // that looks ready.
    if let Some(revocation) = &resp.revocation {
        let r = serde_json::to_value(revocation).unwrap_or_default();
        let sequence = &r["head"]["sequence"];
        let fix = format!(
            "pnm rooms owner revoke --room {} --signing-key <the room's signing key> --host {}",
            resp.room_id, resp.host
        );
        match r["status"].as_str() {
            Some("inForce") => {
                println!("  The room's revocation list (sequence {sequence}) is in force there.")
            }
            Some("refused") => println!(
                "  WARNING: {} refused the room's revocation list (sequence {sequence}): {}. \
                 It serves this room WITHOUT its withdrawals — every credential the room \
                 withdrew is honoured there. Your VTA will not deliver it again on its own. \
                 Do not register again to fix this: deliver the list with\n    {fix}\n  \
                 and if the host refuses again, the refusal says why.",
                resp.host,
                r["code"].as_str().unwrap_or("no code given"),
            ),
            _ => println!(
                "  WARNING: the room's revocation list (sequence {sequence}) is not yet in \
                 force at {}: it serves this room WITHOUT its withdrawals until it is — every \
                 credential the room withdrew is honoured there. Your VTA keeps delivering it \
                 on its own; to bring the host up to date now, without registering again, run\n    \
                 {fix}",
                resp.host
            ),
        }
    }
    println!(
        "  Next: issue {owner} the room's credentials — `pnm rooms owner issue-membership` and \
         `pnm rooms owner issue-authority --action read,write,curate,admin`, each with --store — \
         and on an attributed or private room found its group with \
         `pnm rooms owner group-create --member {owner}`."
    );
    Ok(())
}

/// Advice for a refusal from the room's signing key, shared by the issuance verbs.
fn issuance_hint(e: impl std::fmt::Display, signing_key_id: &str) -> String {
    format!(
        "{e}\n\nA refusal to sign means this VTA will not let you name `{signing_key_id}` — \
         check it with `pnm keys list --context <id>` (it is the `Signing key:` printed when \
         the room's DID was minted). A missing `credential-write` capability is granted with \
         `pnm acl update <your-did> --capabilities credential-write`."
    )
}

/// `rooms owner invite` — mint a VIC naming `subject` and write it to `out`.
pub async fn cmd_rooms_owner_invite(
    client: &VtaClient,
    room_id: &str,
    signing_key_id: &str,
    subject: &str,
    valid_until: Option<DateTime<Utc>>,
    out: &Path,
) -> CmdResult {
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    // Keyed: the answer is the only copy of the credential.
    let resp = client
        .idempotent(|| client.room_owner_invite(room_id, signing_key_id, subject, valid_until))
        .await
        .map_err(|e| issuance_hint(e, signing_key_id))?;
    write_new(out, resp.credential.as_bytes())?;
    println!(
        "Invited {subject} to {room_id}: wrote {} ({}).",
        out.display(),
        resp.credential_id
    );
    println!(
        "  Next: deliver it to the joiner directly. Their side runs `pnm rooms keys key-package \
         --room {room_id} --invitation <file> --out kp.b64` and sends you kp.b64 for \
         `pnm rooms owner group-add`."
    );
    Ok(())
}

/// Which credential an issuance verb mints, for its output.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum IssuedKind {
    Membership,
    Authority,
}

/// What to do with an issued credential: write it, store it, or both.
pub struct IssuedOutput<'a> {
    pub out: Option<&'a Path>,
    pub store: bool,
}

async fn deliver_issued(
    client: &VtaClient,
    kind: IssuedKind,
    subject: &str,
    room_id: &str,
    credential: &str,
    credential_id: &str,
    output: &IssuedOutput<'_>,
) -> CmdResult {
    let name = match kind {
        IssuedKind::Membership => "a membership credential",
        IssuedKind::Authority => "an authority credential",
    };
    if let Some(out) = output.out {
        write_new(out, credential.as_bytes())?;
        println!(
            "Issued {subject} {name} for {room_id}: wrote {} ({credential_id}).",
            out.display()
        );
    } else {
        println!("Issued {subject} {name} for {room_id} ({credential_id}).");
    }
    if output.store {
        let body: serde_json::Value = serde_json::from_str(credential)
            .map_err(|e| format!("the VTA's credential is not JSON: {e}"))?;
        client.cred_vault_receive(body, None).await.map_err(|e| {
            let saved = output
                .out
                .map(|p| format!(" It is saved in {}; retry with `pnm cred-vault receive --credential-file {}`.", p.display(), p.display()))
                .unwrap_or_default();
            format!("issued, but this VTA's credential vault refused it: {e}.{saved}")
        })?;
        println!(
            "  Stored in this VTA's credential vault, where its presentation oracle finds it."
        );
    } else if let Some(out) = output.out {
        println!(
            "  Next: {subject}'s own VTA stores it — on their side, \
             `pnm cred-vault receive --credential-file {}`.",
            out.display()
        );
    }
    Ok(())
}

/// Refuse an issuance whose credential would go nowhere.
fn require_destination(output: &IssuedOutput<'_>) -> CmdResult {
    if output.out.is_none() && !output.store {
        return Err(
            "the credential would go nowhere: pass --out <file> to write it, --store to keep it \
             in this VTA's credential vault (when the subject is your own persona), or both"
                .into(),
        );
    }
    if let Some(out) = output.out
        && out.exists()
    {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    Ok(())
}

/// `rooms owner issue-membership` — mint a VMC naming `subject`.
pub async fn cmd_rooms_owner_issue_membership(
    client: &VtaClient,
    room_id: &str,
    signing_key_id: &str,
    subject: &str,
    valid_until: Option<DateTime<Utc>>,
    output: IssuedOutput<'_>,
) -> CmdResult {
    require_destination(&output)?;
    let resp = client
        .idempotent(|| {
            client.room_owner_issue_membership(room_id, signing_key_id, subject, valid_until)
        })
        .await
        .map_err(|e| issuance_hint(e, signing_key_id))?;
    deliver_issued(
        client,
        IssuedKind::Membership,
        subject,
        room_id,
        &resp.credential,
        &resp.credential_id,
        &output,
    )
    .await
}

/// `rooms owner issue-authority` — mint a VAC root conferring `actions`.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_rooms_owner_issue_authority(
    client: &VtaClient,
    room_id: &str,
    signing_key_id: &str,
    subject: &str,
    actions: &[String],
    valid_until: Option<DateTime<Utc>>,
    output: IssuedOutput<'_>,
) -> CmdResult {
    let actions = parse_actions(actions)?;
    // Required by the specification and never defaulted: a root is the grant
    // nothing else withdraws, so its expiry is a number the owner must choose.
    let valid_until = valid_until.ok_or(
        "an authority credential needs an expiry: pass --valid-for <duration> (e.g. 90d) or \
         --valid-until <RFC 3339 time>. A chain root is withdrawn by nothing else.",
    )?;
    require_destination(&output)?;
    let resp = client
        .idempotent(|| {
            client.room_owner_issue_authority(
                room_id,
                signing_key_id,
                subject,
                actions.clone(),
                valid_until,
            )
        })
        .await
        .map_err(|e| issuance_hint(e, signing_key_id))?;
    deliver_issued(
        client,
        IssuedKind::Authority,
        subject,
        room_id,
        &resp.credential,
        &resp.credential_id,
        &output,
    )
    .await
}

// ─── The joiner's key holder ─────────────────────────────────────────────

/// Advice for a refused invitation, shared by `key-package` and `welcome`.
fn invitation_hint(e: impl std::fmt::Display) -> String {
    format!(
        "{e}\n\nThe invitation must be the one the room issued to your persona, unexpired and \
         unused: ask the owner for a fresh one (`pnm rooms owner invite --subject <your persona \
         DID>`). {PERSONA_HINT}"
    )
}

/// `rooms keys key-package` — mint a KeyPackage against an invitation and write
/// it, base64url, to `out` (the format `rooms owner group-add --key-package` reads).
pub async fn cmd_rooms_keys_key_package(
    client: &VtaClient,
    room_id: &str,
    invitation_src: &str,
    out: &Path,
) -> CmdResult {
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    let invitation = read_text(invitation_src, "invitation")?;
    // `rooms/keys/key-package/0.2` converges: asked again for the same room, member and
    // invitation, the VTA returns the KeyPackage it already holds (`alreadyMinted`).
    let resp = client
        .room_key_package(room_id, &invitation)
        .await
        .map_err(invitation_hint)?;
    write_new(out, format!("{}\n", resp.key_package.as_str()).as_bytes())?;
    let verb = if resp.already_minted {
        "Wrote the KeyPackage this VTA already holds"
    } else {
        "Minted a KeyPackage"
    };
    println!(
        "{verb} for {room_id}: wrote {}, unused until {}.",
        out.display(),
        crate::duration::format_local_datetime(resp.expires_at)
    );
    println!(
        "  Next: send it to the room's owner for `pnm rooms owner group-add --key-package {}`, \
         then join with the Welcome they send back: `pnm rooms keys welcome --room {room_id} \
         --invitation {invitation_src} --welcome <file>`.",
        out.display()
    );
    Ok(())
}

/// The Welcome file `rooms owner group-add --out` writes.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WelcomeFile {
    room_id: Option<String>,
    welcome: String,
    ratchet_tree: Option<String>,
}

/// `rooms keys welcome` — join the room's group from the owner's Welcome.
pub async fn cmd_rooms_keys_welcome(
    client: &VtaClient,
    room_id: &str,
    invitation_src: &str,
    welcome_src: &str,
) -> CmdResult {
    let invitation = read_text(invitation_src, "invitation")?;
    let file: WelcomeFile =
        serde_json::from_str(&read_text(welcome_src, "Welcome")?).map_err(|e| {
            format!("{welcome_src} is not a Welcome written by `pnm rooms owner group-add`: {e}")
        })?;
    if let Some(r) = &file.room_id
        && r != room_id
    {
        return Err(format!(
            "{welcome_src} is a Welcome to room `{r}`, not `{room_id}`; pass --room {r} if that \
             is the room you meant"
        )
        .into());
    }

    // Keyed: a retry that re-executed would find the group held and the
    // invitation spent, and report a refusal over a join that succeeded.
    let resp = client
        .idempotent(|| {
            client.room_welcome(
                room_id,
                &invitation,
                &file.welcome,
                file.ratchet_tree.as_deref(),
            )
        })
        .await
        .map_err(invitation_hint)?;
    // The task answers in MLS epochs (rooms/keys/welcome/0.1); every other room
    // number an operator sees — the host's, `rooms keys list`, `group-add` — is the
    // room epoch, one more.
    println!(
        "Joined {room_id} at room epoch {}. The invitation is now spent.",
        resp.epoch + 1
    );
    println!(
        "  Next: store the membership and authority credentials the owner issues you \
         (`pnm cred-vault receive --credential-file …`). Later membership changes reach this \
         VTA as commits: `pnm rooms keys commit --room {room_id} --host <url> --host-did <did>`."
    );
    Ok(())
}

/// The room epoch a commit relayed at room epoch `room_epoch` produces, as the MLS
/// epoch `rooms/keys/commit/0.1` takes. A room counts from 1, MLS from 0.
pub fn mls_epoch_of(room_epoch: u64) -> Result<NonZeroU64, Box<dyn std::error::Error>> {
    room_epoch
        .checked_sub(1)
        .and_then(NonZeroU64::new)
        .ok_or_else(|| {
            format!(
                "room epoch {room_epoch} is produced by no commit: a room's group starts at \
                 epoch 1, so the first commit produces epoch 2"
            )
            .into()
        })
}

/// `rooms keys commit --commit <file> --epoch <n>` — apply one commit.
pub async fn cmd_rooms_keys_commit_file(
    client: &VtaClient,
    room_id: &str,
    commit_src: &str,
    room_epoch: u64,
) -> CmdResult {
    let commit = read_text(commit_src, "commit")?;
    let resp = client
        .room_commit(room_id, &commit, mls_epoch_of(room_epoch)?)
        .await
        .map_err(commit_hint)?;
    println!("{room_id}: this VTA is at room epoch {}.", resp.epoch + 1);
    Ok(())
}

fn commit_hint(e: impl std::fmt::Display) -> String {
    let text = e.to_string();
    if text.contains("removed this holder") {
        return format!(
            "{text}\n\nYou are no longer a member of this room's group. Nothing written \
             after your removal will open here; what you could read before still does. \
             Rejoining takes a fresh invitation from the room's owner."
        );
    }
    format!(
        "{e}\n\nCommits apply in order. A refusal naming the epoch to resume from means one is \
         missing: fetch them all from the host with `--host <url> --host-did <did>` instead of a \
         file. `no group state` means this VTA never joined — `pnm rooms keys welcome` first."
    )
}

/// `rooms keys commit --host <url>` — fetch the commits this VTA missed from the
/// host's relay (`rooms/epoch/commits`), read as the member, and apply them in order.
pub async fn cmd_rooms_keys_commit_from_host(
    client: &VtaClient,
    target: RoomTarget<'_>,
) -> CmdResult {
    let room_id = target.room_id;
    let held = held_epoch(client, room_id).await?;

    let mut at = held;
    let mut applied = 0usize;
    let room_epoch = loop {
        let since = u32::try_from(at).map_err(|_| format!("room epoch {at} is out of range"))?;
        let page: vti_rooms::wire::CommitsResponse = super::rooms::act_and_send_parsed(
            client,
            &target,
            vti_rooms::wire::ROOMS_EPOCH_COMMITS_TYPE,
            serde_json::json!({ "roomId": room_id, "sinceEpoch": since }),
        )
        .await?;
        if page.commits.is_empty() {
            break u64::from(page.room_epoch);
        }
        let before = at;
        for c in &page.commits {
            let resp = client
                .room_commit(room_id, &c.commit, mls_epoch_of(u64::from(c.epoch))?)
                .await
                .map_err(commit_hint)?;
            at = resp.epoch + 1;
            applied += 1;
        }
        // A page that moved nothing would be served again: stop rather than spin.
        if at == before || at >= u64::from(page.room_epoch) {
            break u64::from(page.room_epoch);
        }
    };

    println!(
        "{room_id}: applied {applied} commit(s); this VTA is at room epoch {at}, the host at {room_epoch}."
    );
    if at < room_epoch {
        println!(
            "  The host is missing the commit that produces epoch {}: records sealed since will \
             not open here until the room's owner re-delivers it.",
            at + 1
        );
    }
    Ok(())
}

/// The room epoch this VTA's group is at, from `rooms/keys/list`.
async fn held_epoch(client: &VtaClient, room_id: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let list = client.room_list(false).await?;
    list.rooms
        .iter()
        .find(|r| r.room_id.as_str() == room_id)
        .map(|r| r.epoch.get())
        .ok_or_else(|| {
            format!(
                "this VTA holds no group for room `{room_id}`: join it first with \
                 `pnm rooms keys welcome`, or found it with `pnm rooms owner group-create` if \
                 you own it"
            )
            .into()
        })
}

/// `rooms keys backfill` — have this VTA fetch the room's epoch key chain from the host,
/// walking down until it reads the whole retained history or the host has no more.
pub async fn cmd_rooms_keys_backfill(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
) -> CmdResult {
    let mut from: Option<std::num::NonZeroU64> = None;
    let mut fetched = 0u64;
    // `rooms/keys/backfill/0.2` learns and applies the room's epoch floor.
    let mut floor: Option<u64> = None;
    let reach = loop {
        let resp = client.room_backfill(room_id, host_did, from).await?;
        floor = resp.epoch_floor.map(|f| f.0.get()).or(floor);
        let (reach, served) = (
            resp.earliest_readable_epoch.get(),
            resp.fetched.unwrap_or(0),
        );
        fetched += served;
        // Stop at the whole history, at the room's floor, when the host serves nothing
        // more, or when a pass moved nothing — a gap in the chain the host cannot fill.
        if reach <= 1
            || floor.is_some_and(|f| reach <= f)
            || served == 0
            || from.is_some_and(|f| f.get() == reach)
        {
            break reach;
        }
        from = std::num::NonZeroU64::new(reach);
    };
    println!(
        "{room_id}: fetched {fetched} link(s); this VTA now reads back to room epoch {reach}."
    );
    if let Some(f) = floor
        && reach <= f
    {
        println!(
            "  The room's history before epoch {f} was pruned by its owner (its epoch floor): \
             nothing below it is kept here, and nothing will bring it back."
        );
    } else if reach > 1 {
        println!(
            "  Records sealed before epoch {reach} will not open here: the host holds no links \
             below it, or the room's history was deliberately severed there."
        );
    }
    Ok(())
}

/// `rooms keys list` — the rooms this VTA holds a group for, as which member, and the
/// member's own name for each (`rooms/keys/list/0.2` with `includePersonal`).
///
/// The labels are the operator's own and go only to this terminal.
pub async fn cmd_rooms_keys_list(client: &VtaClient) -> CmdResult {
    cmd_rooms_keys_list_named(client, None).await
}

/// `rooms keys list --host-did` — [`cmd_rooms_keys_list`], with each room's own name read
/// from that host (`rooms/keys/profile/read`), as the member each entry is held as.
pub async fn cmd_rooms_keys_list_named(client: &VtaClient, host_did: Option<&str>) -> CmdResult {
    let list = client.room_list(true).await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&list.rooms)?;
        return Ok(());
    }
    if list.rooms.is_empty() {
        println!("This VTA holds no room's group.");
        return Ok(());
    }
    // The trust context each member's key lives in rides in `ext["org.openvtc.rooms"].held`,
    // index for index.
    let held = held_ext(&list.ext);
    // The room's own name, where a host was named: read once per entry, as that entry's
    // member. A room the host does not serve, or that has no profile, simply has none.
    let mut names: Vec<Option<String>> = Vec::with_capacity(list.rooms.len());
    for r in &list.rooms {
        names.push(match host_did {
            Some(host) => client
                .room_profile_read(r.room_id.as_str(), host, Some(r.member.as_str()))
                .await
                .ok()
                .and_then(|p| p.profile.map(|p| inert_line(p.name.as_str()))),
            None => None,
        });
    }
    println!("{} room(s):", list.rooms.len());
    for (i, r) in list.rooms.iter().enumerate() {
        let personal = r.personal.as_ref();
        // Your own name first (rooms/keys/label's display order), then the name the room
        // gives itself, then its DID.
        match (personal.and_then(|p| p.label.as_ref()), &names[i]) {
            (Some(name), _) => println!("  {}  ({})", as_text(name), r.room_id.as_str()),
            (None, Some(name)) => println!("  {name}  ({})", r.room_id.as_str()),
            (None, None) => println!("  {}", r.room_id.as_str()),
        }
        if personal.and_then(|p| p.label.as_ref()).is_some()
            && let Some(name) = &names[i]
        {
            println!("    the room calls itself: {name}");
        }
        let context = held
            .get(i)
            .and_then(|h| h["context"].as_str())
            .map(|c| format!(" (context {c})"))
            .unwrap_or_default();
        println!("    as {}{context}", r.member.as_str());
        println!(
            "    epoch {}, reads back to epoch {}",
            r.epoch, r.earliest_readable_epoch
        );
        if let Some(p) = personal {
            if let Some(d) = &p.description {
                println!("    your description: {}", indent(&as_text(d)));
            }
            if let Some(tags) = &p.tags {
                let tags: Vec<String> = tags.iter().map(|t| as_text(t)).collect();
                println!("    your tags: {}", tags.join(", "));
            }
            if let Some(n) = &p.notes {
                println!("    your notes: {}", indent(&as_text(n)));
            }
        }
    }
    if host_did.is_none() {
        println!("\nAdd --host-did <host> to show the name each room gives itself.");
    }
    Ok(())
}

/// `ext["org.openvtc.rooms"].held`, or nothing.
fn held_ext<E: serde::Serialize>(ext: &E) -> Vec<serde_json::Value> {
    serde_json::to_value(ext)
        .ok()
        .and_then(|e| e.get("org.openvtc.rooms")?.get("held").cloned())
        .and_then(|h| h.as_array().cloned())
        .unwrap_or_default()
}

/// A label's text as a terminal may show it: every control character but a line break or
/// a tab replaced, so nothing in it is acted on as an escape sequence.
fn as_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Continuation lines of a multi-line detail, indented under it.
fn indent(s: &str) -> String {
    s.replace('\n', "\n      ")
}

/// `rooms keys label` — the operator's own name, description, notes and tags for a room
/// (`rooms/keys/label/0.1`). Idempotent: asking again changes nothing and says so.
pub async fn cmd_rooms_keys_label(
    client: &VtaClient,
    room_id: &str,
    member: &str,
    edit: &vta_sdk::client::RoomLabelEdit,
) -> CmdResult {
    let resp = match client.room_label(room_id, member, edit).await {
        Ok(r) => r,
        Err(vta_sdk::error::VtaError::Rejected { code, .. })
            if code == "rooms/keys/label:notHeld" =>
        {
            return Err(format!(
                "this VTA holds no group for room `{room_id}` as `{member}`, or you do not act \
                 as that member. `pnm rooms keys list` shows each room with the member it is \
                 held as — pass that DID as --member."
            )
            .into());
        }
        Err(e) => return Err(e.into()),
    };
    if crate::render::is_json_output() {
        crate::render::print_json(&resp)?;
        return Ok(());
    }
    if !resp.changed {
        println!("{room_id}: your label already says that; nothing changed.");
        return Ok(());
    }
    match &resp.personal {
        None => println!("{room_id}: your label is removed."),
        Some(p) => {
            println!("{room_id}: your label is updated (as {member}).");
            if let Some(name) = &p.label {
                println!("  name: {}", as_text(name));
            }
            if let Some(d) = &p.description {
                println!("  description: {}", indent(&as_text(d)));
            }
            if let Some(tags) = &p.tags {
                let tags: Vec<String> = tags.iter().map(|t| as_text(t)).collect();
                println!("  tags: {}", tags.join(", "));
            }
            if let Some(n) = &p.notes {
                println!("  notes: {}", indent(&as_text(n)));
            }
        }
    }
    Ok(())
}

// ─── The room's own profile ──────────────────────────────────────────────

/// Text another member wrote, made safe to print: control characters (terminal escapes
/// among them) removed, newlines and tabs kept.
fn inert(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// [`inert`], on one line.
fn inert_line(text: &str) -> String {
    inert(text).replace(['\n', '\t'], " ")
}

/// One field of `rooms profile set`: keep what the room has, replace it, or drop it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change<T> {
    Keep,
    Set(T),
    Drop,
}

/// What `rooms profile set` changes. The name is kept when not given.
#[derive(Debug, Clone)]
pub struct ProfileEdit {
    pub name: Option<String>,
    pub description: Change<String>,
    pub tags: Change<Vec<String>>,
    pub emoji: Change<String>,
}

/// The profile `edit` makes of `current` (the room's profile now, as JSON, if it has one):
/// a write replaces the whole profile, so what the operator did not touch is carried over.
fn edited_profile(
    current: Option<&serde_json::Value>,
    edit: ProfileEdit,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut p = current.cloned().unwrap_or_else(|| serde_json::json!({}));
    let Some(obj) = p.as_object_mut() else {
        return Err("the room's current profile is not an object".into());
    };
    if let Some(name) = edit.name {
        obj.insert("name".into(), serde_json::Value::String(name));
    }
    if !obj.contains_key("name") {
        return Err(
            "the room has no profile yet, so give it a name: --name \"<the room's name>\"".into(),
        );
    }
    let mut apply = |key: &str, change: Change<serde_json::Value>| match change {
        Change::Keep => {}
        Change::Set(v) => {
            obj.insert(key.into(), v);
        }
        Change::Drop => {
            obj.remove(key);
        }
    };
    let map = |c: Change<String>| match c {
        Change::Keep => Change::Keep,
        Change::Set(v) => Change::Set(serde_json::Value::String(v)),
        Change::Drop => Change::Drop,
    };
    apply("description", map(edit.description));
    apply("emoji", map(edit.emoji));
    apply(
        "tags",
        match edit.tags {
            Change::Keep => Change::Keep,
            Change::Set(t) => Change::Set(serde_json::json!(t)),
            Change::Drop => Change::Drop,
        },
    );
    Ok(p)
}

/// Print a `rooms/keys/profile/read` answer: the profile as text, and — in words — anybody
/// who tried to rename the room without the standing to.
fn print_profile(room_id: &str, resp: &serde_json::Value) {
    match resp["status"].as_str().unwrap_or_default() {
        "found" => {
            let p = &resp["profile"];
            let emoji = p["emoji"]
                .as_str()
                .map(|e| format!("{} ", inert_line(e)))
                .unwrap_or_default();
            println!(
                "{emoji}{}",
                inert_line(p["name"].as_str().unwrap_or_default())
            );
            if let Some(d) = p["description"].as_str() {
                println!("  {}", inert(d).replace('\n', "\n  "));
            }
            if let Some(tags) = p["tags"].as_array().filter(|t| !t.is_empty()) {
                let tags: Vec<String> = tags
                    .iter()
                    .filter_map(|t| t.as_str().map(inert_line))
                    .collect();
                println!("  tags: {}", tags.join(", "));
            }
            println!(
                "  named by {} at {}{}",
                resp["author"].as_str().unwrap_or("?"),
                resp["issuedAt"].as_str().unwrap_or("?"),
                resp["epoch"]
                    .as_u64()
                    .map(|e| format!(", under epoch {e}"))
                    .unwrap_or_default()
            );
            if resp["stale"].as_bool() == Some(true) {
                println!(
                    "  This profile predates the room's latest epoch and was not written again \
                     since; it may be out of date."
                );
            }
        }
        "cleared" => println!("Room {room_id} has no profile: a curator cleared it."),
        _ => println!(
            "Room {room_id} has not given itself a name you can read{}.",
            resp["searched"]["toEpoch"]
                .as_u64()
                .map(|e| format!(" (looked down to epoch {e})"))
                .unwrap_or_default()
        ),
    }
    for r in resp["rejected"].as_array().into_iter().flatten() {
        let reason = r["reason"].as_str().unwrap_or_default();
        let who = r["author"].as_str().unwrap_or("somebody");
        let at = r["epoch"]
            .as_u64()
            .map(|e| format!(" under epoch {e}"))
            .unwrap_or_default();
        match reason {
            "noAuthority" | "timing" | "revoked" => println!(
                "  ! {who} wrote a newer profile{at} without the standing to name the room \
                 ({reason}); it is ignored."
            ),
            _ => println!("  ! a newer profile record{at} was ignored ({reason})."),
        }
    }
}

/// `rooms profile show` — what the room calls itself.
pub async fn cmd_rooms_profile_show(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    member: Option<&str>,
) -> CmdResult {
    let resp = client.room_profile_read(room_id, host_did, member).await?;
    let resp = serde_json::to_value(&resp)?;
    if crate::render::is_json_output() {
        crate::render::print_json(&resp)?;
        return Ok(());
    }
    print_profile(room_id, &resp);
    Ok(())
}

/// `rooms profile set` — set the room's profile, carrying over what the operator did not
/// change from the profile it has now.
pub async fn cmd_rooms_profile_set(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    edit: ProfileEdit,
    member: Option<&str>,
) -> CmdResult {
    let current = client.room_profile_read(room_id, host_did, member).await?;
    let current = current.profile.map(serde_json::to_value).transpose()?;
    let profile = edited_profile(current.as_ref(), edit)?;
    let profile =
        serde_json::from_value(profile).map_err(|e| format!("that is not a room profile: {e}"))?;
    let out = client
        .room_profile_write(room_id, host_did, &profile, member)
        .await
        .map_err(|e| profile_refusal(e, room_id))?;
    let out = serde_json::to_value(&out)?;
    if crate::render::is_json_output() {
        crate::render::print_json(&out)?;
        return Ok(());
    }
    println!(
        "Named room {room_id}{}. Every member reads it with `pnm rooms profile show`.",
        out["epoch"]
            .as_u64()
            .map(|e| format!(" under epoch {e}"))
            .unwrap_or_default()
    );
    Ok(())
}

/// `rooms profile clear` — retract the room's profile.
pub async fn cmd_rooms_profile_clear(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    member: Option<&str>,
) -> CmdResult {
    let out = client
        .room_profile_clear(room_id, host_did, member)
        .await
        .map_err(|e| profile_refusal(e, room_id))?;
    let out = serde_json::to_value(&out)?;
    if crate::render::is_json_output() {
        crate::render::print_json(&out)?;
        return Ok(());
    }
    println!("Cleared room {room_id}'s profile.");
    Ok(())
}

/// A `rooms/keys/profile/write` refusal, with what to do about the two an operator meets.
fn profile_refusal(e: vta_sdk::error::VtaError, room_id: &str) -> Box<dyn std::error::Error> {
    let text = e.to_string();
    if text.contains("noAuthority") {
        return format!(
            "{text}\n\nNaming a room takes `write` and `curate` or `admin` in it; clearing takes \
             `curate`. The room's owner grants them with `pnm rooms owner issue-authority --room \
             {room_id} --subject <your persona DID> --action write,curate --valid-for 90d --store`."
        )
        .into();
    }
    if text.contains("contended") {
        return format!(
            "{text}\n\nOther writes kept landing in the room; run the same command again."
        )
        .into();
    }
    e.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rooms profile set` replaces the whole profile, so what is not given is carried over
    /// and `--no-*` drops it.
    #[test]
    fn a_profile_edit_carries_over_what_it_does_not_touch() {
        let current = serde_json::json!({
            "name": "Board", "description": "Papers", "tags": ["board"], "emoji": "📋",
        });
        let renamed = edited_profile(
            Some(&current),
            ProfileEdit {
                name: Some("Board pack".into()),
                description: Change::Keep,
                tags: Change::Keep,
                emoji: Change::Drop,
            },
        )
        .unwrap();
        assert_eq!(
            renamed,
            serde_json::json!({ "name": "Board pack", "description": "Papers", "tags": ["board"] })
        );
        let retagged = edited_profile(
            Some(&current),
            ProfileEdit {
                name: None,
                description: Change::Drop,
                tags: Change::Set(vec!["a".into(), "b".into()]),
                emoji: Change::Keep,
            },
        )
        .unwrap();
        assert_eq!(
            retagged,
            serde_json::json!({ "name": "Board", "tags": ["a", "b"], "emoji": "📋" })
        );
        assert!(
            edited_profile(
                None,
                ProfileEdit {
                    name: None,
                    description: Change::Set("x".into()),
                    tags: Change::Keep,
                    emoji: Change::Keep,
                },
            )
            .is_err(),
            "a room with no profile needs a name"
        );
    }

    /// Another member's text never drives the terminal.
    #[test]
    fn profile_text_is_inert() {
        assert_eq!(
            inert_line("Board\u{1b}[31m pack\nnext"),
            "Board[31m pack next"
        );
    }

    #[test]
    fn validity_takes_either_form_and_refuses_the_past() {
        assert!(validity(None, None).unwrap().is_none());
        let soon = validity(None, Some("1h")).unwrap().unwrap();
        assert!(soon > Utc::now());
        assert!(
            validity(Some("2999-01-01T00:00:00Z"), None)
                .unwrap()
                .is_some()
        );
        assert!(
            validity(Some("2000-01-01T00:00:00Z"), None).is_err(),
            "past"
        );
        assert!(validity(Some("tomorrow"), None).is_err(), "not RFC 3339");
        assert!(validity(Some("2999-01-01T00:00:00Z"), Some("1h")).is_err());
    }

    #[test]
    fn a_label_is_shown_as_text_never_as_escapes() {
        assert_eq!(as_text("Book\u{1b}[31m club"), "Book\u{FFFD}[31m club");
        assert_eq!(as_text("a\u{9b}b\rc"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(as_text("line\n\tnext — ok"), "line\n\tnext — ok");
    }

    #[test]
    fn actions_are_the_four_and_never_none() {
        assert!(parse_actions(&[]).is_err());
        assert_eq!(
            parse_actions(&["read".into(), "admin".into()])
                .unwrap()
                .len(),
            2
        );
        assert!(parse_actions(&["everything".into()]).is_err());
    }

    /// A commit relayed at room epoch n produces MLS epoch n - 1; room epoch 1 is
    /// the group's founding and has no commit.
    #[test]
    fn room_epochs_map_onto_mls_epochs() {
        assert_eq!(mls_epoch_of(2).unwrap().get(), 1);
        assert_eq!(mls_epoch_of(7).unwrap().get(), 6);
        assert!(mls_epoch_of(1).is_err());
        assert!(mls_epoch_of(0).is_err());
    }

    #[test]
    fn an_issuance_with_nowhere_to_go_is_refused() {
        assert!(
            require_destination(&IssuedOutput {
                out: None,
                store: false
            })
            .is_err()
        );
        assert!(
            require_destination(&IssuedOutput {
                out: None,
                store: true
            })
            .is_ok()
        );
    }

    #[test]
    fn a_welcome_file_from_group_add_parses() {
        let f: WelcomeFile = serde_json::from_value(serde_json::json!({
            "roomId": "did:webvh:room", "member": "did:webvh:bob", "epoch": 2,
            "welcome": "AAEC", "ratchetTree": null,
        }))
        .unwrap();
        assert_eq!(f.welcome, "AAEC");
        assert!(f.ratchet_tree.is_none());
    }
}
