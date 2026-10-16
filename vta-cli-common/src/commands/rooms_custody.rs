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
/// (`rooms/owner/register/0.1`), signing `rooms/create` as `owner`.
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
    // Keyed: the answer is the only copy of the package, and its private half is
    // already retained against it.
    let resp = client
        .idempotent(|| client.room_key_package(room_id, &invitation))
        .await
        .map_err(invitation_hint)?;
    write_new(out, format!("{}\n", resp.key_package).as_bytes())?;
    let expiry = resp
        .expires_at
        .map(|t| {
            format!(
                ", unused until {}",
                crate::duration::format_local_datetime(t)
            )
        })
        .unwrap_or_default();
    println!(
        "Minted a KeyPackage for {room_id}: wrote {}{expiry}.",
        out.display()
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
    let list = client.room_keys_list().await?;
    list.rooms
        .iter()
        .find(|r| r.room_id == room_id)
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
    let reach = loop {
        let resp = client.room_backfill(room_id, host_did, from).await?;
        let reach = resp.earliest_readable_epoch.get();
        let served = resp.fetched.unwrap_or(0);
        fetched += served;
        // Stop at the whole history, when the host serves nothing more, or when a pass
        // moved nothing — a gap in the chain the host cannot fill.
        if reach <= 1 || served == 0 || from.is_some_and(|f| f.get() == reach) {
            break reach;
        }
        from = std::num::NonZeroU64::new(reach);
    };
    println!(
        "{room_id}: fetched {fetched} link(s); this VTA now reads back to room epoch {reach}."
    );
    if reach > 1 {
        println!(
            "  Records sealed before epoch {reach} will not open here: the host holds no links \
             below it, or the room's history was deliberately severed there."
        );
    }
    Ok(())
}

/// `rooms keys list` — the rooms this VTA holds a group for.
pub async fn cmd_rooms_keys_list(client: &VtaClient) -> CmdResult {
    let list = client.room_keys_list().await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&list.rooms)?;
        return Ok(());
    }
    if list.rooms.is_empty() {
        println!("This VTA holds no room's group.");
        return Ok(());
    }
    // Whose each entry is rides in `ext["org.openvtc.rooms"].held`, index for index: a VTA
    // holding two members of one room (the community's own place and an administrator's
    // own membership) lists the room twice, and only this tells the two apart.
    let held = serde_json::to_value(&list.ext)
        .ok()
        .and_then(|e| e.get("org.openvtc.rooms")?.get("held").cloned())
        .and_then(|h| h.as_array().cloned())
        .unwrap_or_default();
    println!("{} room(s):", list.rooms.len());
    for (i, r) in list.rooms.iter().enumerate() {
        println!(
            "  {}  epoch {}  reads back to epoch {}",
            r.room_id, r.epoch, r.earliest_readable_epoch
        );
        if let Some(member) = held.get(i).and_then(|h| h["member"].as_str()) {
            let context = held[i]["context"]
                .as_str()
                .map(|c| format!(" (context {c})"))
                .unwrap_or_default();
            println!("    as {member}{context}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
