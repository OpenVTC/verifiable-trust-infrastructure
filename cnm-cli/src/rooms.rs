//! `cnm rooms …` — the data rooms the community itself **owns**
//! (`vtc/rooms/community/*`, `docs/05-design-notes/data-rooms-files.md` §8.4).
//!
//! The community is the owner and its own VTA holds each room's keys: this command never
//! signs as a room, holds a room key or sees a credential. It signs a request as this
//! profile's administrator identity, and the VTC has its VTA do the rest — mint the room's
//! identity, found its group, issue a member's credentials. A change (`create`,
//! `members add`, `members remove`) takes a passkey gesture bound to that one request,
//! answered in a browser as `cnm git` changes are; reads take none, and neither does
//! `update` — a room's label, description and tags are the community's own record and
//! reach no key holder. Every one needs `vtc.rooms.manage` on this profile's entry.
//!
//! A room is closed in two deliberate steps (`vtc/rooms/community/{archive,unarchive,
//! remove,removal/cancel}/0.1`): `archive` (read-only, or no access — reversible with
//! `unarchive`), then `remove`, which purges the content after a grace period that
//! `cancel-removal` calls off, or at once with `--now`. `archive`, `unarchive` and `remove`
//! take a passkey gesture; `cancel-removal` takes none, so stopping a mistaken removal is
//! never harder than making it. `list` and `get` show each room's state (`get`/`list` 0.4).
//!
//! Members collect and accept their offers with their own DID (`vtc/rooms/offers/*`), from
//! the member portal or their wallet — not from an administrator's profile.

use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use vta_cli_common::duration::parse_duration_secs;
use vta_cli_common::render::{BOLD, DIM, RESET, bin_name, is_json_output, print_json};
use vtc_client::community_rooms as spec;
use vtc_client::git_ns::task_error;
use vtc_client::{HolderKey, VtcClient, VtcError};

use vta_sdk::session::TransportChoice;

use crate::git::{did_arg, send_change, signing_key, terminal_safe};
use crate::vtc::{self as vtc_target, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// `cnm rooms …`
#[derive(Subcommand)]
pub enum RoomsCommands {
    /// Create a room the community owns. Its VTA mints the room's identity and holds its
    /// keys; the community hosts it. The tier is fixed for the room's life.
    Create {
        /// A name administrators and invited members see. Not personal data.
        #[arg(long)]
        label: String,
        /// What the room is for, shown to administrators and to the members it is offered
        /// to. Plain text, up to 1000 characters; not personal data.
        #[arg(long)]
        description: Option<String>,
        /// A tag to file the room under (repeat, up to 8): lower-case letters, digits and
        /// hyphens. Administrators only — never shown to members.
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long, value_enum)]
        visibility: VisibilityArg,
        /// Whether a member reads the room's history from before they joined. Default
        /// `chained` (they do).
        #[arg(long, value_enum)]
        retention_policy: Option<RetentionArg>,
        /// Days the room is kept after it lapses. Default: the community's.
        #[arg(long)]
        retention_days: Option<u32>,
        /// The storage config to receive the room's files. Default: the community's.
        #[arg(long)]
        storage_config: Option<String>,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// The rooms the community owns — every state but removed, unless asked.
    List {
        /// Only the rooms filed under this tag.
        #[arg(long)]
        tag: Option<String>,
        /// Only the rooms in this state (repeat).
        #[arg(long = "state", value_enum, conflicts_with = "all")]
        states: Vec<RoomStateArg>,
        /// Every room, removed ones included.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// One room the community owns.
    Get {
        /// The room's DID.
        room: String,
    },
    /// Rename a room the community owns, or change its description or tags. Each one given
    /// replaces what the room has; the rest are left as they are. Takes no passkey: it
    /// reaches no key holder and changes nobody's access.
    Update {
        /// The room's DID.
        room: String,
        /// Its new name.
        #[arg(long)]
        label: Option<String>,
        /// Its new description, replacing any it has.
        #[arg(long, conflicts_with = "remove_description")]
        description: Option<String>,
        /// Remove its description.
        #[arg(long)]
        remove_description: bool,
        /// Its tags (repeat), replacing the whole set.
        #[arg(long = "tag", conflicts_with = "clear_tags")]
        tags: Vec<String>,
        /// Remove every tag.
        #[arg(long)]
        clear_tags: bool,
        /// Why — recorded in the audit trail with the earlier values.
        #[arg(long)]
        reason: String,
    },
    /// Archive a room: it admits no one, its open offers are withdrawn, and its host
    /// accepts no writes. `read-only` keeps members reading; `no-access` withdraws every
    /// credential the room issued (a reset) and keeps the content. Reversible with
    /// `unarchive`. On an archived room, moves it to the other access.
    Archive {
        /// The room's DID.
        room: String,
        #[arg(long, value_enum)]
        access: AccessArg,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Reopen an archived room. Members suspended by `no-access` are restored: the room
    /// re-issues their credentials, which they collect as a renewal.
    Unarchive {
        /// The room's DID.
        room: String,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Remove an archived room: everyone's access is withdrawn and its content is purged
    /// after a grace period (the community's default unless given), or at once with
    /// `--now`. The purge cannot be undone; until it starts, `cancel-removal` calls it off.
    Remove {
        /// The room's DID.
        room: String,
        /// Days to keep the content before purging it (0–365).
        #[arg(long, conflicts_with = "now")]
        grace_days: Option<u32>,
        /// Purge at once: no grace period, and nothing to cancel.
        #[arg(long)]
        now: bool,
        /// The room's label, typed exactly, to confirm which room is removed.
        #[arg(long)]
        confirm: String,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Call off a scheduled removal before its purge begins. The room stays archived
    /// with no access. Takes no passkey.
    CancelRemoval {
        /// The room's DID.
        room: String,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Who the community has admitted to one of its rooms, or offered admission.
    Members {
        #[command(subcommand)]
        command: MembersCommands,
    },
}

/// `cnm rooms members …`
#[derive(Subcommand)]
pub enum MembersCommands {
    /// Offer a community member admission: the VTA issues their invitation, membership and
    /// authority, which the VTC keeps for them to collect and accept.
    Add {
        /// The room's DID.
        room: String,
        /// The member's DID — the persona their own VTA holds, as the community knows them.
        #[arg(long)]
        member: String,
        /// What they may do (repeat): `read`, `write`, `curate`. `admin` stays the
        /// community's.
        #[arg(long = "action", value_enum, required = true)]
        actions: Vec<ActionArg>,
        /// How long their authority lasts (`90d`, `12h`). On an open room, removal takes
        /// effect only when this runs out — keep it short there.
        #[arg(long, conflicts_with = "valid_until")]
        valid_for: Option<String>,
        /// When their authority ends (RFC 3339).
        #[arg(long)]
        valid_until: Option<String>,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Remove a member, or withdraw an open offer. On an open or attributed room the
    /// room's host refuses their credentials from then on; on a sealed room the room also
    /// advances to an epoch sealed to everyone else. A private room cannot withdraw one
    /// member: there they leave the group, and their credentials last until they expire.
    Remove {
        /// The room's DID.
        room: String,
        #[arg(long)]
        member: String,
        /// Why — recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// The room's members and offers.
    List {
        /// The room's DID.
        room: String,
        #[arg(long, value_enum)]
        state: Option<StateArg>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum VisibilityArg {
    Open,
    Attributed,
    Private,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RetentionArg {
    Chained,
    FromJoin,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ActionArg {
    Read,
    Write,
    Curate,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StateArg {
    Offered,
    Admitted,
    Suspended,
    Removed,
}

/// A room's state in its owner's lifecycle (`RoomState`).
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
pub enum RoomStateArg {
    Active,
    Archived,
    RemovalScheduled,
    Purging,
    Removed,
}

impl RoomStateArg {
    /// As the wire names it.
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::RemovalScheduled => "removalScheduled",
            Self::Purging => "purging",
            Self::Removed => "removed",
        }
    }
}

/// What an archived room's members may still do (`ArchiveAccess`).
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
pub enum AccessArg {
    ReadOnly,
    NoAccess,
}

impl AccessArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "readOnly",
            Self::NoAccess => "noAccess",
        }
    }
}

impl VisibilityArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attributed => "attributed",
            Self::Private => "private",
        }
    }
}

impl ActionArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Curate => "curate",
        }
    }
}

impl StateArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Admitted => "admitted",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }
}

pub async fn run(
    command: RoomsCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_task(command, &vtc.client, keyring_key, target).await;
    vtc.client.shutdown().await;
    outcome
}

/// `payload`, read as the generated request type: what is signed is exactly what the
/// specification defines, and a bad argument is caught before anything is signed.
fn typed<P: serde::de::DeserializeOwned + serde::Serialize>(payload: Value) -> CliResult<Value> {
    let p: P = serde_json::from_value(payload)?;
    Ok(serde_json::to_value(p)?)
}

/// What the operator should do about a refusal, where there is something to do.
fn hint(code: &str) -> &'static str {
    match code {
        "permissionDenied" => {
            "\nThis needs `vtc.rooms.manage` on this profile's entry: an administrator \
             holding `vtc.roles.assign` grants it (`cnm access …`)."
        }
        "vtc/rooms/community/create:noKeyHolder" => {
            "\nThe VTC's operator turns community rooms on: a `[rooms.community]` section \
             naming the context at the community's VTA, and the VTC's messaging link to it."
        }
        "vtc/rooms/community/create:visibilityNotPermitted" => {
            "\nThe community's `rooms` policy decides which tiers it may own a room at; \
             `private` is off until an operator uploads a policy that permits it."
        }
        "vtc/rooms/community/update:notFound"
        | "vtc/rooms/community/get:notFound"
        | "vtc/rooms/community/archive:notFound"
        | "vtc/rooms/community/unarchive:notFound"
        | "vtc/rooms/community/remove:notFound"
        | "vtc/rooms/community/removal/cancel:notFound" => {
            "\nThis community owns no room with that DID. A room it only hosts belongs to its \
             member owner, and its name is theirs: `cnm rooms list` shows the community's own."
        }
        "vtc/rooms/community/members/add:notAMember" => {
            "\nOnly active members of the community are admitted to its rooms."
        }
        "vtc/rooms/community/create:keyHolderUnavailable"
        | "vtc/rooms/community/members/add:keyHolderUnavailable"
        | "vtc/rooms/community/members/remove:keyHolderUnavailable" => {
            "\nThe community's VTA did not answer; nothing was recorded. Run the same \
             command again."
        }
        "vtc/rooms/community/archive:keyHolderUnavailable"
        | "vtc/rooms/community/unarchive:keyHolderUnavailable"
        | "vtc/rooms/community/remove:keyHolderUnavailable" => {
            "\nThe community's VTA did not answer. If the room's credentials were already \
             reset, `rooms get` shows a pending change: the VTC finishes it by itself, and \
             running the same command again finishes it too."
        }
        _ => "",
    }
}

/// The state a lifecycle refusal names, read from its message — `room `…` is <state>` from
/// the lifecycle tasks, or `members/add`'s wording. The refusal's `details.state` says the
/// same, but a change's error reaches this command as text.
fn refused_state(message: &str) -> Option<RoomStateArg> {
    let m = message;
    if m.contains(" is removalScheduled") || m.contains("scheduled for removal") {
        Some(RoomStateArg::RemovalScheduled)
    } else if m.contains(" is purging") || m.contains("being purged") {
        Some(RoomStateArg::Purging)
    } else if m.contains(" is removed") || m.contains(" was removed") {
        Some(RoomStateArg::Removed)
    } else if m.contains(" is archived") {
        Some(RoomStateArg::Archived)
    } else if m.contains(" is active") {
        Some(RoomStateArg::Active)
    } else {
        None
    }
}

/// The command that fixes a lifecycle refusal on `room`, verbatim — `None` when there is
/// none to give.
fn lifecycle_fix(code: &str, message: &str, room: &str) -> Option<String> {
    if !code.ends_with(":wrongState") {
        return None;
    }
    let bin = bin_name();
    let room = terminal_safe(room);
    let task = code
        .strip_prefix("vtc/rooms/community/")?
        .strip_suffix(":wrongState")?;
    let state = refused_state(message)?;
    match (task, state) {
        ("remove", RoomStateArg::Active) => Some(format!(
            "\nA room is removed only once it is archived. Archive it first:\n  \
             {bin} rooms archive {room} --access no-access --reason \"…\""
        )),
        ("archive" | "unarchive", RoomStateArg::RemovalScheduled) => Some(format!(
            "\nIts removal is scheduled. Call it off first (it stays archived with no access):\n  \
             {bin} rooms cancel-removal {room} --reason \"…\""
        )),
        ("members/add", RoomStateArg::Archived) => Some(format!(
            "\nAn archived room admits no one. Reopen it first:\n  \
             {bin} rooms unarchive {room} --reason \"…\""
        )),
        (_, RoomStateArg::Purging | RoomStateArg::Removed) => {
            Some("\nIts content is being or has been deleted; that cannot be undone.".to_string())
        }
        ("removal/cancel", RoomStateArg::Archived) => {
            Some("\nNo removal is scheduled: the room is archived.".to_string())
        }
        _ => None,
    }
}

/// `change`, with the room-exact command for a lifecycle refusal appended.
async fn change_on_room(
    client: &VtcClient,
    base: &str,
    type_uri: &str,
    payload: Value,
    did: &str,
    key: &HolderKey,
    room: &str,
) -> CliResult<Value> {
    change(client, base, type_uri, payload, did, key)
        .await
        .map_err(|e| {
            let text = e.to_string();
            let fix = refused_code(&text).and_then(|code| {
                let message = text.split_once("): ").map(|(_, m)| m).unwrap_or_default();
                lifecycle_fix(code, message, room)
            });
            match fix {
                Some(f) => format!("{text}{f}").into(),
                None => e,
            }
        })
}

/// What archiving with `access` does, and does not — said before anything is signed
/// (`archive/0.1` producer item 1).
fn archive_preview(access: AccessArg) -> &'static str {
    match access {
        AccessArg::ReadOnly => {
            "Archiving read-only: members keep reading; the room's host refuses every write, \
             upload and curation; nobody new is admitted and every open offer is withdrawn. \
             It recalls nothing anyone already read, and on a sealed tier removes nobody from \
             the room's group. `rooms unarchive` reopens it."
        }
        AccessArg::NoAccess => {
            "Archiving with no access: the room is reset — every credential it issued, from \
             everyone, is withdrawn at its host — and every admitted member is suspended; every \
             open offer is withdrawn. The content is kept. It recalls nothing anyone already \
             read or saved, and on a sealed tier removes nobody from the room's group. \
             `rooms unarchive` reopens it and restores suspended members."
        }
    }
}

/// `--confirm` must name the room's label exactly.
fn confirm_label(label: &str, confirm: &str, room: &str) -> CliResult {
    if confirm == label {
        return Ok(());
    }
    Err(format!(
        "--confirm does not match this room's label, so nothing was sent. To remove `{}`, \
         confirm with its label exactly:\n  --confirm {}",
        terminal_safe(room),
        shell_quote(label)
    )
    .into())
}

/// `s` quoted for a POSIX shell.
fn shell_quote(s: &str) -> String {
    format!("'{}'", terminal_safe(s).replace('\'', "'\\''"))
}

/// The `states` of a `list/0.4` request: the ones named, every state for `--all`, or none
/// (the community lists every state but `removed`).
fn list_states(states: &[RoomStateArg], all: bool) -> Option<Vec<&'static str>> {
    if all {
        return Some(vec![
            "active",
            "archived",
            "removalScheduled",
            "purging",
            "removed",
        ]);
    }
    if states.is_empty() {
        return None;
    }
    let mut out: Vec<&'static str> = Vec::new();
    for s in states {
        if !out.contains(&s.as_str()) {
            out.push(s.as_str());
        }
    }
    Some(out)
}

/// A room's `status` (`RoomStatus`), in words — the lines under its heading.
fn status_lines(room: &Value) -> Vec<String> {
    let st = &room["status"];
    let Some(state) = st["state"].as_str() else {
        return Vec::new();
    };
    let t = |k: &str| st[k].as_str().map(terminal_safe);
    let mut out = Vec::new();
    let head = match state {
        "active" => None,
        "archived" => Some(match st["access"].as_str() {
            Some("readOnly") => "archived, read-only: members read; nobody writes".to_string(),
            _ => "archived, no access: every member's credentials withdrawn; content kept"
                .to_string(),
        }),
        "removalScheduled" => Some(format!(
            "removal scheduled: content purged at {} (`rooms cancel-removal` calls it off)",
            t("purgeAt").unwrap_or_default()
        )),
        "purging" => Some("being purged: its content is being deleted".to_string()),
        "removed" => Some(format!(
            "removed {}: only this record remains",
            t("removedAt").unwrap_or_default()
        )),
        other => Some(terminal_safe(other)),
    };
    if let Some(h) = head {
        let since = match (t("changedAt"), t("changedBy")) {
            (Some(at), Some(by)) if state != "removed" => format!(" (since {at}, by {by})"),
            _ => String::new(),
        };
        out.push(format!("{h}{since}"));
    }
    if state == "purging" {
        let p = &st["purge"];
        let mut line = format!("purge attempts {}", p["attempts"]);
        if let Some(next) = p["nextAttemptAt"].as_str() {
            line.push_str(&format!(", next {}", terminal_safe(next)));
        }
        if let Some(e) = p["lastError"].as_str() {
            line.push_str(&format!(" (last: {})", terminal_safe(e)));
        }
        out.push(line);
    }
    if let Some(p) = st.get("pendingChange").filter(|p| p.is_object()) {
        let mut line = format!(
            "a change to {}{} begun {} has not finished; the VTC finishes it, and repeating \
             the command finishes it too",
            terminal_safe(p["state"].as_str().unwrap_or_default()),
            p["access"]
                .as_str()
                .map(|a| format!(" ({})", terminal_safe(a)))
                .unwrap_or_default(),
            terminal_safe(p["beganAt"].as_str().unwrap_or_default()),
        );
        if let Some(e) = p["lastError"].as_str() {
            line.push_str(&format!(" (last: {})", terminal_safe(e)));
        }
        out.push(line);
    }
    if let Some(n) = st["restoring"].as_u64() {
        out.push(format!(
            "restoring {n} suspended member(s): each collects re-issued credentials as a \
             renewal (`pnm rooms offers renew`)"
        ));
    }
    out
}

fn explain(err: VtcError) -> Box<dyn std::error::Error> {
    match task_error(&err) {
        Some((code, message)) => format!(
            "the community refused it ({}): {}{}",
            terminal_safe(&code),
            terminal_safe(&message),
            hint(&code)
        )
        .into(),
        None => err.to_string().into(),
    }
}

/// Whether a refusal says the VTC does not serve the version asked for.
fn unsupported(err: &VtcError) -> bool {
    task_error(err)
        .is_some_and(|(code, _)| matches!(code.as_str(), "unsupportedType" | "unsupportedVersion"))
}

/// A signed read: no step-up.
async fn read(
    client: &VtcClient,
    type_uri: &str,
    payload: Value,
    key: &HolderKey,
) -> CliResult<Value> {
    let doc = client.git_ns_sign(type_uri, &payload, key).await?;
    match client.git_ns_send_signed::<Value>(type_uri, &doc).await {
        Ok(v) => Ok(v),
        Err(e) if unsupported(&e) => Err(format!(
            "{}\nThis VTC does not serve {type_uri}: upgrade it.",
            explain(e)
        )
        .into()),
        Err(e) => Err(explain(e)),
    }
}

/// A change: through the passkey gesture it asks for. A refusal is rewritten with its fix
/// — for one the community's entry at its VTA explains, the `pnm` commands that fix it.
async fn change(
    client: &VtcClient,
    base: &str,
    type_uri: &str,
    payload: Value,
    did: &str,
    key: &HolderKey,
) -> CliResult<Value> {
    match send_change(client, base, type_uri, &payload, did, key).await {
        Ok(v) => Ok(v),
        Err(e) => {
            let text = e.to_string();
            let code = refused_code(&text).unwrap_or_default();
            let fix = match vta_fix(client, key, code, &text).await {
                Some(f) => f,
                None => hint(code).to_string(),
            };
            Err(format!("{text}{fix}").into())
        }
    }
}

/// What `roomProfile` in a create or update answer means, in words — `None` when it needs
/// no comment.
fn room_profile_said(v: &Value) -> Option<&'static str> {
    match v["roomProfile"].as_str()? {
        "written" => Some(
            "The room's label and description are written into the room: its members read them as its name.",
        ),
        "pending" => Some(
            "The room's name is not written into the room yet: the community's VTA has not answered. The VTC keeps trying; `rooms get` shows how it stands.",
        ),
        _ => None,
    }
}

/// Whether a refusal could be one the community's entry at its VTA explains.
fn may_be_vta_permission(code: &str) -> bool {
    code.starts_with("vtc/rooms/community/")
        && (code.ends_with(":keyHolderRefused") || code.ends_with(":noKeyHolder"))
}

/// The `pnm` commands for a refusal the community's entry at its VTA explains, from the
/// listing's `ext["org.openvtc"].communityRooms.vtaAccess` — the VTC says its VTA contexts
/// there, to a holder of `vtc.rooms.manage`, and never in a refusal's message.
async fn vta_fix(client: &VtcClient, key: &HolderKey, code: &str, message: &str) -> Option<String> {
    if !may_be_vta_permission(code) {
        return None;
    }
    let type_uri = <spec::list::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI;
    let payload = typed::<spec::list::v0_4::Payload>(json!({ "limit": 1 })).ok()?;
    let listed = read(client, type_uri, payload, key).await.ok()?;
    let access = listed.pointer("/ext/org.openvtc/communityRooms/vtaAccess")?;
    pick_fix(access, code, message).map(render_fix)
}

/// The first fix on the listing whose `when` names the refusal's code and, if it lists
/// any, a phrase its message contains (`vtc_service::rooms::vta_access::Fix::matches`).
fn pick_fix<'a>(access: &'a Value, code: &str, message: &str) -> Option<&'a Value> {
    let short = code.rsplit(':').next().unwrap_or(code);
    access["fixes"].as_array()?.iter().find(|f| {
        f["when"].as_array().into_iter().flatten().any(|w| {
            let phrases: Vec<&str> = w["messageContains"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            w["refusal"].as_str() == Some(short)
                && (phrases.is_empty() || phrases.iter().any(|p| message.contains(p)))
        })
    })
}

/// A fix as the terminal shows it: what is wrong, each command on its own line under what
/// it is for, the check, and who runs them.
fn render_fix(fix: &Value) -> String {
    let s = |k: &str| terminal_safe(fix[k].as_str().unwrap_or_default());
    let mut out = format!("\n\n{}\n", s("summary"));
    for c in fix["commands"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "\n  {DIM}# {}{RESET}\n  {}\n",
            terminal_safe(c["purpose"].as_str().unwrap_or_default()),
            terminal_safe(c["command"].as_str().unwrap_or_default()),
        ));
    }
    out.push_str(&format!("\nthen check:\n  {}\n\n{}", s("check"), s("note")));
    out
}

/// The code in a refusal `cnm git`'s guidance phrased as
/// `the community refused it (<code>): <message>`.
fn refused_code(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("the community refused it (")?;
    rest.split_once("):").map(|(code, _)| code)
}

fn valid_until(valid_for: Option<&str>, valid_until: Option<&str>) -> CliResult<String> {
    match (valid_for, valid_until) {
        (Some(d), None) => {
            let secs = parse_duration_secs(d)?;
            let until = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
            Ok(until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        }
        (None, Some(t)) => {
            let t = chrono::DateTime::parse_from_rfc3339(t)
                .map_err(|e| format!("--valid-until is not an RFC 3339 time: {e}"))?;
            Ok(t.with_timezone(&chrono::Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        }
        _ => Err(
            "name how long the member's authority lasts: --valid-for 90d, or --valid-until <time>"
                .into(),
        ),
    }
}

fn print_room(room: &Value) {
    let r = &room["room"];
    let tags = room_tags(room);
    println!(
        "{BOLD}{}{RESET} — {} · {} · epoch {} · {}{}",
        terminal_safe(room["label"].as_str().unwrap_or_default()),
        terminal_safe(r["roomId"].as_str().unwrap_or_default()),
        r["visibility"].as_str().unwrap_or_default(),
        r["epoch"],
        r["lifecycle"].as_str().unwrap_or_default(),
        if tags.is_empty() {
            String::new()
        } else {
            format!(" · [{}]", terminal_safe(&tags.join(", ")))
        },
    );
    // Administrator-written text: printed as text, never followed as instructions.
    if let Some(d) = room["description"].as_str() {
        println!("  {}", terminal_safe(d));
    }
    for line in status_lines(room) {
        println!("  {BOLD}{line}{RESET}");
    }
    println!(
        "  {DIM}admitted {} · offered {}{} · storage {} · the community's authority until {}{RESET}",
        room["admitted"],
        room["offered"],
        room["suspended"]
            .as_u64()
            .map(|n| format!(" · suspended {n}"))
            .unwrap_or_default(),
        terminal_safe(room["storageConfig"].as_str().unwrap_or("-")),
        room["ownerAuthorityValidUntil"].as_str().unwrap_or("-"),
    );
    if let (Some(at), Some(by)) = (
        room["detailsUpdatedAt"].as_str(),
        room["detailsUpdatedBy"].as_str(),
    ) {
        println!(
            "  {DIM}details last changed {} by {}{RESET}",
            terminal_safe(at),
            terminal_safe(by)
        );
    }
}

/// How a room's own profile stands, from `ext["org.openvtc"].roomProfile`: written into
/// the room, still being written, or never (a room made before create 0.3).
fn room_profile_state(state: &Value) -> String {
    match state["state"].as_str().unwrap_or_default() {
        "written" => format!(
            "name written into the room{}",
            state["writtenAt"]
                .as_str()
                .map(|t| format!(" {}", terminal_safe(t)))
                .unwrap_or_default()
        ),
        "pending" => format!(
            "name not written into the room yet — retrying{}{}",
            state["nextAttemptAt"]
                .as_str()
                .map(|t| format!(", next {}", terminal_safe(t)))
                .unwrap_or_default(),
            state["lastError"]
                .as_str()
                .map(|e| format!(" (last: {})", terminal_safe(e)))
                .unwrap_or_default()
        ),
        _ => format!(
            "name never written into the room: `{} rooms update <room> --label <its label> --reason …` writes it",
            bin_name()
        ),
    }
}

fn room_tags(room: &Value) -> Vec<&str> {
    room["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// `vtc/rooms/community/update/0.3`'s payload; an error when it would name no change.
#[allow(clippy::too_many_arguments)]
fn update_payload(
    room: &str,
    label: Option<String>,
    description: Option<String>,
    remove_description: bool,
    tags: Vec<String>,
    clear_tags: bool,
    reason: String,
) -> CliResult<Value> {
    let mut payload = json!({ "roomId": room, "reason": reason });
    if let Some(l) = label {
        payload["label"] = json!(l);
    }
    if let Some(d) = description {
        payload["description"] = json!(d);
    } else if remove_description {
        payload["removeDescription"] = json!(true);
    }
    if clear_tags {
        payload["tags"] = json!([]);
    } else if !tags.is_empty() {
        payload["tags"] = json!(dedup(tags));
    }
    if payload.as_object().is_some_and(|o| o.len() < 3) {
        return Err(
            "name what to change: --label, --description, --remove-description, \
             --tag or --clear-tags"
                .into(),
        );
    }
    typed::<spec::update::v0_3::Payload>(payload)
}

/// Tags as a set, in the order first given.
fn dedup(tags: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

fn print_member(m: &Value) {
    let actions: Vec<&str> = m["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    println!(
        "{} — {} ({}) until {}",
        terminal_safe(m["member"].as_str().unwrap_or_default()),
        m["state"].as_str().unwrap_or_default(),
        actions.join(", "),
        m["validUntil"].as_str().unwrap_or_default(),
    );
}

fn print_next(v: &Value) {
    if let Some(next) = v["nextCursor"].as_str() {
        println!("{DIM}more: --cursor {}{RESET}", terminal_safe(next));
    }
}

async fn run_task(
    command: RoomsCommands,
    client: &VtcClient,
    keyring_key: &str,
    target: &VtcTarget,
) -> CliResult {
    let (did, key) = signing_key(keyring_key)?;
    match command {
        RoomsCommands::Create {
            label,
            description,
            tags,
            visibility,
            retention_policy,
            retention_days,
            storage_config,
            reason,
        } => {
            let mut payload = json!({
                "label": label,
                "visibility": visibility.as_str(),
                "reason": reason,
            });
            if let Some(p) = retention_policy {
                payload["retentionPolicy"] = json!(match p {
                    RetentionArg::Chained => "chained",
                    RetentionArg::FromJoin => "fromJoin",
                });
            }
            if let Some(d) = retention_days {
                payload["retentionDays"] = json!(d);
            }
            if let Some(c) = storage_config {
                payload["storageConfig"] = json!(c);
            }
            if let Some(d) = description {
                payload["description"] = json!(d);
            }
            if !tags.is_empty() {
                payload["tags"] = json!(dedup(tags));
            }
            // 0.4: the label and description are also written into the room as its profile.
            let type_uri = <spec::create::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let payload = typed::<spec::create::v0_4::Payload>(payload)?;
            let v = change(client, &target.base, type_uri, payload, &did, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            if let Some(said) = room_profile_said(&v) {
                println!("{said}");
            }
            println!(
                "The community's VTA holds the room's keys. Offer members admission with \
                 `{} rooms members add {} --member <did> --action read --valid-for 90d --reason …`.",
                bin_name(),
                terminal_safe(v["room"]["room"]["roomId"].as_str().unwrap_or_default()),
            );
            Ok(())
        }
        RoomsCommands::List {
            tag,
            states,
            all,
            limit,
            cursor,
        } => {
            let mut payload = json!({});
            if let Some(s) = list_states(&states, all) {
                payload["states"] = json!(s);
            }
            if let Some(l) = limit {
                payload["limit"] = json!(l);
            }
            if let Some(c) = cursor {
                payload["cursor"] = json!(c);
            }
            if let Some(t) = &tag {
                payload["tag"] = json!(t);
            }
            // 0.4: each room's state in its owner's lifecycle (`status`).
            let payload = typed::<spec::list::v0_4::Payload>(payload)?;
            let type_uri = <spec::list::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v = read(client, type_uri, payload, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            if let Some(off) = v.pointer("/ext/org.openvtc/communityRooms")
                && off["enabled"] == false
            {
                println!(
                    "Community rooms are off on this VTC. Its operator adds to its config:\n{}",
                    terminal_safe(off["configure"].as_str().unwrap_or_default())
                );
            }
            // The VTC's configuration looks wrong for its entry at its VTA.
            if let Some(access) = v.pointer("/ext/org.openvtc/communityRooms/vtaAccess")
                && let Some(warning) = access["warning"].as_str()
            {
                eprintln!(
                    "{BOLD}Check the community's entry at its VTA:{RESET} {}",
                    terminal_safe(warning)
                );
                if let Some(scope) = access["fixes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|f| f["id"] == "scope")
                {
                    eprintln!("{}", render_fix(scope).trim_start());
                }
            }
            let items = v["items"].as_array().cloned().unwrap_or_default();
            if items.is_empty() {
                match &tag {
                    Some(t) => println!("No room is filed under `{}`.", terminal_safe(t)),
                    None if !states.is_empty() => println!("No room is in that state."),
                    None => println!("The community owns no rooms."),
                }
            }
            for room in &items {
                print_room(room);
                let id = room["room"]["roomId"].as_str().unwrap_or_default();
                if let Some(state) = v
                    .pointer("/ext/org.openvtc/roomProfile")
                    .and_then(|p| p.get(id))
                {
                    println!("  {DIM}{}{RESET}", room_profile_state(state));
                }
            }
            print_next(&v);
            Ok(())
        }
        RoomsCommands::Get { room } => {
            let payload = typed::<spec::get::v0_4::Payload>(json!({ "roomId": room }))?;
            let type_uri = <spec::get::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v = read(client, type_uri, payload, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            if let Some(state) = v.pointer("/ext/org.openvtc/roomProfile") {
                println!("  {DIM}{}{RESET}", room_profile_state(state));
            }
            if let Some(d) = v
                .pointer("/ext/org.openvtc/lifecycle/didRetirement")
                .and_then(Value::as_str)
            {
                println!("  {DIM}the room's DID: {}{RESET}", terminal_safe(d));
            }
            Ok(())
        }
        RoomsCommands::Archive {
            room,
            access,
            reason,
        } => {
            let payload = typed::<spec::archive::v0_1::Payload>(json!({
                "roomId": room,
                "access": access.as_str(),
                "reason": reason,
            }))?;
            if !is_json_output() {
                eprintln!("{}", archive_preview(access));
            }
            let type_uri = <spec::archive::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v =
                change_on_room(client, &target.base, type_uri, payload, &did, &key, &room).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            if v["changed"] == true {
                println!("Archived.");
            } else {
                println!("Nothing changed: the room was already archived that way.");
            }
            if let Some(n) = v["withdrawnOffers"].as_u64() {
                println!("{n} open offer(s) withdrawn.");
            }
            if let Some(at) = v["revokedAt"].as_str() {
                println!(
                    "The room's host refuses the withdrawn credentials from {} (revocation list {}).",
                    terminal_safe(at),
                    v["revocation"]["sequence"]
                );
            }
            Ok(())
        }
        RoomsCommands::Unarchive { room, reason } => {
            let payload = typed::<spec::unarchive::v0_1::Payload>(json!({
                "roomId": room,
                "reason": reason,
            }))?;
            let type_uri = <spec::unarchive::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v =
                change_on_room(client, &target.base, type_uri, payload, &did, &key, &room).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            if v["changed"] == true {
                println!(
                    "Unarchived. Open offers withdrawn by the archive are not restored: make them again."
                );
            } else {
                println!("Nothing changed: the room is already active.");
            }
            if let Some(n) = v.pointer("/room/status/restoring").and_then(Value::as_u64) {
                println!(
                    "{n} suspended member(s) are being restored: the room re-issues their \
                     credentials, which each collects as a renewal (`pnm rooms offers renew`)."
                );
            }
            Ok(())
        }
        RoomsCommands::Remove {
            room,
            grace_days,
            now,
            confirm,
            reason,
        } => {
            // Which room, by the label administrators know it by — checked before anything
            // is signed (`remove/0.1` producer item).
            let get = typed::<spec::get::v0_4::Payload>(json!({ "roomId": room }))?;
            let get_uri = <spec::get::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let current = read(client, get_uri, get, &key).await?;
            let label = current["room"]["label"].as_str().unwrap_or_default();
            confirm_label(label, &confirm, &room)?;
            let mut payload = json!({ "roomId": room, "reason": reason });
            if now {
                payload["graceDays"] = json!(0);
            } else if let Some(d) = grace_days {
                payload["graceDays"] = json!(d);
            }
            let payload = typed::<spec::remove::v0_1::Payload>(payload)?;
            if !is_json_output() {
                if now {
                    eprintln!(
                        "{BOLD}Removing now:{RESET} everyone's access is withdrawn and the \
                         room's content is deleted at once. This cannot be undone. It recalls \
                         nothing anyone already read or saved."
                    );
                } else {
                    eprintln!(
                        "Removing: everyone's access is withdrawn and the content is kept until \
                         the grace period ends, then deleted. `rooms cancel-removal` calls it off \
                         until then. It recalls nothing anyone already read or saved."
                    );
                }
            }
            let type_uri = <spec::remove::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v =
                change_on_room(client, &target.base, type_uri, payload, &did, &key, &room).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            match v.pointer("/room/status/state").and_then(Value::as_str) {
                Some("removalScheduled") => println!(
                    "Removal scheduled: the content is purged at {}. To call it off before then:\n  \
                     {} rooms cancel-removal {} --reason \"…\"",
                    terminal_safe(
                        v.pointer("/room/status/purgeAt")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                    ),
                    bin_name(),
                    terminal_safe(&room),
                ),
                Some("purging") | Some("removed") => println!(
                    "The purge has begun. `{} rooms get {}` shows when it finishes.",
                    bin_name(),
                    terminal_safe(&room),
                ),
                _ => {}
            }
            Ok(())
        }
        RoomsCommands::CancelRemoval { room, reason } => {
            let payload = typed::<spec::removal::cancel::v0_1::Payload>(json!({
                "roomId": room,
                "reason": reason,
            }))?;
            let type_uri =
                <spec::removal::cancel::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v =
                change_on_room(client, &target.base, type_uri, payload, &did, &key, &room).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            println!(
                "The removal is called off. The room stays archived with no access; \
                 `{} rooms unarchive {}` reopens it.",
                bin_name(),
                terminal_safe(&room)
            );
            Ok(())
        }
        RoomsCommands::Update {
            room,
            label,
            description,
            remove_description,
            tags,
            clear_tags,
            reason,
        } => {
            let payload = update_payload(
                &room,
                label,
                description,
                remove_description,
                tags,
                clear_tags,
                reason,
            )?;
            // A new label or description is written into the room as its profile too.
            let type_uri = <spec::update::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v = change(client, &target.base, type_uri, payload, &did, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            if v["changed"] == true {
                println!("Changed. The earlier values are in the community's audit trail.");
            } else {
                println!("Nothing changed: the room already had those details.");
            }
            if let Some(said) = room_profile_said(&v) {
                println!("{said}");
            }
            Ok(())
        }
        RoomsCommands::Members { command } => match command {
            MembersCommands::Add {
                room,
                member,
                actions,
                valid_for,
                valid_until: until,
                reason,
            } => {
                let member = did_arg("--member", &member)?;
                let mut acts: Vec<&str> = Vec::new();
                for a in actions {
                    if !acts.contains(&a.as_str()) {
                        acts.push(a.as_str());
                    }
                }
                let until = valid_until(valid_for.as_deref(), until.as_deref())?;
                // 0.2: an archived room, or one on its way out, admits no one (`wrongState`).
                let payload = typed::<spec::members::add::v0_2::Payload>(json!({
                    "roomId": room,
                    "member": member,
                    "actions": acts,
                    "validUntil": until,
                    "reason": reason,
                }))?;
                let type_uri =
                    <spec::members::add::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
                let v = change_on_room(client, &target.base, type_uri, payload, &did, &key, &room)
                    .await?;
                if is_json_output() {
                    return Ok(print_json(&v)?);
                }
                print_member(&v["member"]);
                println!(
                    "Offered. The member collects the offer and accepts it with their own DID \
                     (vtc/rooms/offers/{{list,accept}}), from the member portal or their wallet."
                );
                Ok(())
            }
            MembersCommands::Remove {
                room,
                member,
                reason,
            } => {
                let member = did_arg("--member", &member)?;
                // 0.2: on `open` and `attributed` rooms the member's credentials are
                // withdrawn at the room's host too, from `revokedAt` (trust-tasks-tf #804).
                let payload = typed::<spec::members::remove::v0_2::Payload>(json!({
                    "roomId": room,
                    "member": member,
                    "reason": reason,
                }))?;
                let type_uri =
                    <spec::members::remove::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
                let v = change(client, &target.base, type_uri, payload, &did, &key).await?;
                if is_json_output() {
                    return Ok(print_json(&v)?);
                }
                print_member(&v["member"]);
                if let Some(at) = v["revokedAt"].as_str() {
                    println!(
                        "The room's host refuses their credentials, and anything they delegated, \
                         from {} (revocation list {}).",
                        terminal_safe(at),
                        v["revocation"]["sequence"]
                    );
                } else if let Some(until) = v.pointer("/member/validUntil").and_then(Value::as_str)
                {
                    println!(
                        "A private room cannot withdraw one member: a host honours their \
                         credentials until {}.",
                        terminal_safe(until)
                    );
                }
                if let Some(epoch) = v["epoch"].as_u64() {
                    println!("The room is now at epoch {epoch}, sealed to everyone else.");
                }
                if let Some(notice) = v.pointer("/ext/org.openvtc/notice").and_then(Value::as_str) {
                    println!("{DIM}{}{RESET}", terminal_safe(notice));
                }
                Ok(())
            }
            MembersCommands::List {
                room,
                state,
                limit,
                cursor,
            } => {
                let mut payload = json!({ "roomId": room });
                if let Some(s) = state {
                    payload["state"] = json!(s.as_str());
                }
                if let Some(l) = limit {
                    payload["limit"] = json!(l);
                }
                if let Some(c) = cursor {
                    payload["cursor"] = json!(c);
                }
                // 0.2: `suspended` — withdrawn while the room is closed to its members.
                let payload = typed::<spec::members::list::v0_2::Payload>(payload)?;
                let type_uri =
                    <spec::members::list::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
                let v = read(client, type_uri, payload, &key).await?;
                if is_json_output() {
                    return Ok(print_json(&v)?);
                }
                let items = v["items"].as_array().cloned().unwrap_or_default();
                if items.is_empty() {
                    println!("Nobody.");
                }
                for m in &items {
                    print_member(m);
                }
                print_next(&v);
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// create 0.3 / update 0.2's `roomProfile`, and get/list's profile state, in words —
    /// nothing said for an older VTC that sends neither.
    #[test]
    fn the_rooms_profile_state_is_said_in_words() {
        assert!(
            room_profile_said(&json!({ "roomProfile": "written" }))
                .unwrap()
                .contains("written into the room")
        );
        assert!(
            room_profile_said(&json!({ "roomProfile": "pending" }))
                .unwrap()
                .contains("keeps trying")
        );
        assert!(room_profile_said(&json!({ "roomProfile": "unchanged" })).is_none());
        assert!(room_profile_said(&json!({})).is_none());
        assert!(room_profile_state(&json!({ "state": "written" })).starts_with("name written"));
        let pending = room_profile_state(&json!({
            "state": "pending", "nextAttemptAt": "2026-10-17T10:00:00Z", "lastError": "unreachable",
        }));
        assert!(
            pending.contains("retrying") && pending.contains("unreachable"),
            "{pending}"
        );
        assert!(room_profile_state(&json!({ "state": "none" })).contains("rooms update"));
    }

    #[test]
    fn an_expiry_is_named_one_way() {
        assert!(valid_until(Some("90d"), None).is_ok());
        assert!(valid_until(None, Some("2027-10-01T00:00:00Z")).is_ok());
        assert!(valid_until(None, None).is_err());
        assert!(valid_until(None, Some("next week")).is_err());
    }

    #[test]
    fn a_payload_outside_the_specification_is_caught_before_signing() {
        let ok = typed::<spec::members::add::v0_2::Payload>(json!({
            "roomId": "did:key:z6MkRoom", "member": "did:key:z6MkMember",
            "actions": ["read"], "validUntil": "2027-10-01T00:00:00Z", "reason": "r",
        }));
        assert!(ok.is_ok());
        let admin = typed::<spec::members::add::v0_2::Payload>(json!({
            "roomId": "did:key:z6MkRoom", "member": "did:key:z6MkMember",
            "actions": ["admin"], "validUntil": "2027-10-01T00:00:00Z", "reason": "r",
        }));
        assert!(admin.is_err(), "admin stays the community's");
    }

    fn access() -> Value {
        json!({
            "vtcDid": "did:webvh:Qm:example.com:test-vtc",
            "fixes": [
                {
                    "id": "noEntry",
                    "when": [
                        { "refusal": "keyHolderRefused", "messageContains": ["DID not in ACL"] },
                        { "refusal": "noKeyHolder" },
                    ],
                    "summary": "The VTC's DID needs an entry at its VTA.",
                    "commands": [{ "purpose": "create it", "command": "pnm acl create --did did:webvh:Qm:example.com:test-vtc --role initiator --contexts vtc-test" }],
                    "note": "Run these with pnm as someone with admin at the community's VTA.",
                    "check": "pnm acl list --context vtc-test --direction any",
                },
                {
                    "id": "scope",
                    "when": [{ "refusal": "keyHolderRefused", "messageContains": ["persona you may act as"] }],
                    "summary": "The entry does not cover vtc-test.",
                    "commands": [{ "purpose": "scope it", "command": "pnm acl update did:webvh:Qm:example.com:test-vtc --contexts vtc-test" }],
                    "note": "Run these with pnm as someone with admin at the community's VTA.",
                    "check": "pnm acl list --context vtc-test --direction any",
                },
            ],
        })
    }

    #[test]
    fn a_vta_permission_refusal_prints_the_commands_from_the_listing() {
        let a = access();
        let code = "vtc/rooms/community/create:keyHolderRefused";
        let persona = "the community refused it (vtc/rooms/community/create:keyHolderRefused): \
                       the community's VTA refused: permissionDenied `did:x` is not a persona \
                       you may act as";
        let fix = pick_fix(&a, code, persona).unwrap();
        assert_eq!(fix["id"], "scope");
        let text = render_fix(fix);
        assert!(text.contains(
            "\n  pnm acl update did:webvh:Qm:example.com:test-vtc --contexts vtc-test\n"
        ));
        assert!(text.contains("pnm acl list --context vtc-test --direction any"));
        assert!(text.contains("admin at the community's VTA"));

        assert_eq!(
            pick_fix(&a, "vtc/rooms/community/create:noKeyHolder", "x").unwrap()["id"],
            "noEntry"
        );
        assert!(pick_fix(&a, code, "malformedRequest").is_none());
        assert!(may_be_vta_permission(code));
        assert!(!may_be_vta_permission("permissionDenied"));
        assert!(!may_be_vta_permission(
            "vtc/rooms/community/create:keyHolderUnavailable"
        ));
    }

    #[test]
    fn an_update_names_only_what_changes() {
        let p = update_payload(
            "did:key:z6MkRoom",
            Some("Board pack — 2027".into()),
            None,
            true,
            vec!["board".into(), "finance".into(), "board".into()],
            false,
            "the 2027 cycle".into(),
        )
        .unwrap();
        assert_eq!(p["label"], "Board pack — 2027");
        assert_eq!(p["removeDescription"], true);
        assert!(p.get("description").is_none());
        assert_eq!(p["tags"], json!(["board", "finance"]));

        let cleared = update_payload(
            "did:key:z6MkRoom",
            None,
            None,
            false,
            Vec::new(),
            true,
            "r".into(),
        )
        .unwrap();
        assert_eq!(
            cleared["tags"],
            json!([]),
            "--clear-tags sends an empty set"
        );
        assert!(cleared.get("label").is_none());

        let nothing = update_payload(
            "did:key:z6MkRoom",
            None,
            None,
            false,
            Vec::new(),
            false,
            "r".into(),
        );
        assert!(
            nothing.is_err(),
            "an update that names nothing is caught before signing"
        );

        let bad_tag = update_payload(
            "did:key:z6MkRoom",
            None,
            None,
            false,
            vec!["Board Pack".into()],
            false,
            "r".into(),
        );
        assert!(
            bad_tag.is_err(),
            "a tag outside the specification is caught before signing"
        );
    }

    #[test]
    fn a_lifecycle_refusal_names_the_command_that_fixes_it() {
        let room = "did:webvh:example.com:rooms:board";
        let fix = lifecycle_fix(
            "vtc/rooms/community/remove:wrongState",
            "room `did:webvh:example.com:rooms:board` is active — archive it first",
            room,
        )
        .unwrap();
        assert!(fix.contains(&format!("rooms archive {room} --access no-access --reason")));
        let fix = lifecycle_fix(
            "vtc/rooms/community/archive:wrongState",
            "room `x` is removalScheduled — its removal is scheduled",
            room,
        )
        .unwrap();
        assert!(fix.contains(&format!("rooms cancel-removal {room}")));
        let fix = lifecycle_fix(
            "vtc/rooms/community/unarchive:wrongState",
            "room `x` is removalScheduled",
            room,
        )
        .unwrap();
        assert!(fix.contains("rooms cancel-removal"));
        let fix = lifecycle_fix(
            "vtc/rooms/community/members/add:wrongState",
            "room `x` is archived: it admits no one until it is unarchived",
            room,
        )
        .unwrap();
        assert!(fix.contains(&format!("rooms unarchive {room}")));
        assert!(
            lifecycle_fix(
                "vtc/rooms/community/remove:wrongState",
                "room `x` is purging — its content is being or has been deleted",
                room
            )
            .unwrap()
            .contains("cannot be undone")
        );
        assert!(lifecycle_fix("vtc/rooms/community/remove:notFound", "is active", room).is_none());
        assert!(
            hint("vtc/rooms/community/archive:keyHolderUnavailable").contains("pending change")
        );
        assert!(hint("vtc/rooms/community/remove:notFound").contains("cnm rooms list"));
    }

    #[test]
    fn removal_is_confirmed_by_the_rooms_exact_label() {
        assert!(confirm_label("Board pack", "Board pack", "did:x").is_ok());
        let err = confirm_label("Board pack", "board pack", "did:x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing was sent"), "{err}");
        assert!(err.contains("--confirm 'Board pack'"), "{err}");
        let quoted = confirm_label("Bob's room", "x", "did:x")
            .unwrap_err()
            .to_string();
        assert!(quoted.contains(r"--confirm 'Bob'\''s room'"), "{quoted}");
    }

    #[test]
    fn the_state_filter_maps_to_the_wire_names() {
        assert_eq!(list_states(&[], false), None);
        assert_eq!(
            list_states(
                &[
                    RoomStateArg::Archived,
                    RoomStateArg::RemovalScheduled,
                    RoomStateArg::Archived
                ],
                false
            ),
            Some(vec!["archived", "removalScheduled"])
        );
        assert_eq!(list_states(&[], true).unwrap().len(), 5);
        assert!(list_states(&[], true).unwrap().contains(&"removed"));
        let p = typed::<spec::list::v0_4::Payload>(json!({
            "states": list_states(&[RoomStateArg::Purging], false),
        }));
        assert!(p.is_ok(), "{p:?}");
    }

    #[test]
    fn a_rooms_state_is_said_in_words() {
        assert!(status_lines(&json!({ "status": { "state": "active" } })).is_empty());
        let ro = status_lines(&json!({ "status": {
            "state": "archived", "access": "readOnly",
            "changedAt": "2026-11-02T10:00:00Z", "changedBy": "did:key:zA",
        } }));
        assert!(
            ro[0].contains("read-only") && ro[0].contains("did:key:zA"),
            "{ro:?}"
        );
        let scheduled = status_lines(&json!({ "status": {
            "state": "removalScheduled", "access": "noAccess", "purgeAt": "2026-12-02T10:00:00Z",
        } }));
        assert!(
            scheduled[0].contains("2026-12-02T10:00:00Z"),
            "{scheduled:?}"
        );
        let purging = status_lines(&json!({ "status": {
            "state": "purging", "purge": { "attempts": 2, "lastError": "storage down" },
        } }));
        assert!(purging[1].contains("storage down"), "{purging:?}");
        let pending = status_lines(&json!({ "status": {
            "state": "active",
            "pendingChange": { "state": "archived", "access": "noAccess", "beganAt": "t" },
            "restoring": 3,
        } }));
        assert!(pending[0].contains("has not finished"), "{pending:?}");
        assert!(pending[1].contains("restoring 3"), "{pending:?}");
        assert!(archive_preview(AccessArg::NoAccess).contains("suspended"));
        assert!(archive_preview(AccessArg::ReadOnly).contains("members keep reading"));
    }

    #[test]
    fn a_refusal_names_its_fix() {
        assert!(hint("permissionDenied").contains("vtc.rooms.manage"));
        assert!(hint("vtc/rooms/community/create:noKeyHolder").contains("[rooms.community]"));
        assert!(hint("something-else").is_empty());
        assert!(hint("vtc/rooms/community/update:notFound").contains("cnm rooms list"));
        assert_eq!(
            refused_code("the community refused it (permissionDenied): no"),
            Some("permissionDenied")
        );
        assert_eq!(refused_code("the step-up was not completed"), None);
    }
}
