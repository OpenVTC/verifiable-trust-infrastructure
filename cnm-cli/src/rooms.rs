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
    /// The rooms the community owns.
    List {
        /// Only the rooms filed under this tag.
        #[arg(long)]
        tag: Option<String>,
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
    Removed,
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
        "vtc/rooms/community/update:notFound" | "vtc/rooms/community/get:notFound" => {
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
        _ => "",
    }
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

/// A signed read at 0.2, the version that carries each room's description and tags — and,
/// from a VTC that does not serve it yet, the same read at 0.1 when `fallback` is given.
async fn read_v0_2(
    client: &VtcClient,
    type_uri: &str,
    payload: Value,
    fallback: Option<(&str, Value)>,
    key: &HolderKey,
) -> CliResult<Value> {
    let doc = client.git_ns_sign(type_uri, &payload, key).await?;
    match client.git_ns_send_signed::<Value>(type_uri, &doc).await {
        Ok(v) => Ok(v),
        Err(e) if unsupported(&e) => match fallback {
            Some((uri, p)) => read(client, uri, p, key).await,
            None => Err(format!(
                "{}\nThis VTC does not serve {type_uri} yet: upgrade it to filter by tag.",
                explain(e)
            )
            .into()),
        },
        Err(e) => Err(explain(e)),
    }
}

/// A signed read: no step-up.
async fn read(
    client: &VtcClient,
    type_uri: &str,
    payload: Value,
    key: &HolderKey,
) -> CliResult<Value> {
    let doc = client.git_ns_sign(type_uri, &payload, key).await?;
    client
        .git_ns_send_signed::<Value>(type_uri, &doc)
        .await
        .map_err(explain)
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

/// [`change`] at the newest of `versions` (task URI and payload, newest first) the VTC
/// serves: a refusal saying it does not serve one (`unsupportedType` /
/// `unsupportedVersion`) asks again at the next. The first was never routed, so asking
/// again is not a retry of the change.
async fn change_at_newest(
    client: &VtcClient,
    base: &str,
    versions: Vec<(&str, Value)>,
    did: &str,
    key: &HolderKey,
) -> CliResult<Value> {
    let last = versions.len().saturating_sub(1);
    for (i, (type_uri, payload)) in versions.into_iter().enumerate() {
        match change(client, base, type_uri, payload, did, key).await {
            Err(e)
                if i < last
                    && refused_code(&e.to_string())
                        .is_some_and(|c| matches!(c, "unsupportedType" | "unsupportedVersion")) => {
            }
            other => return other,
        }
    }
    Err("no version of this task to send".into())
}

/// What `roomProfile` in a create 0.3 / update 0.2 answer means, in words — `None` when it
/// was not sent (an older VTC) or needs no comment.
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
    let type_uri = <spec::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
    let payload = typed::<spec::list::v0_1::Payload>(json!({ "limit": 1 })).ok()?;
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
    println!(
        "  {DIM}admitted {} · offered {} · storage {} · the community's authority until {}{RESET}",
        room["admitted"],
        room["offered"],
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

/// `vtc/rooms/community/update/0.1`'s payload. `None` when nothing would change.
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
    typed::<spec::update::v0_1::Payload>(payload)
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
            // 0.3, which also writes the label and description into the room as its profile;
            // a VTC that predates it gets 0.2 — and 0.1 when there is nothing only 0.2 carries.
            let v0_1 = typed::<spec::create::v0_1::Payload>(payload.clone())?;
            let plain = description.is_none() && tags.is_empty();
            if let Some(d) = description {
                payload["description"] = json!(d);
            }
            if !tags.is_empty() {
                payload["tags"] = json!(dedup(tags));
            }
            let mut versions = vec![
                (
                    <spec::create::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    typed::<spec::create::v0_3::Payload>(payload.clone())?,
                ),
                (
                    <spec::create::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    typed::<spec::create::v0_2::Payload>(payload)?,
                ),
            ];
            if plain {
                versions.push((
                    <spec::create::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    v0_1,
                ));
            }
            let v = change_at_newest(client, &target.base, versions, &did, &key).await?;
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
        RoomsCommands::List { tag, limit, cursor } => {
            let mut payload = json!({});
            if let Some(l) = limit {
                payload["limit"] = json!(l);
            }
            if let Some(c) = cursor {
                payload["cursor"] = json!(c);
            }
            // Without a tag, a VTC that serves only 0.1 still lists its rooms.
            let fallback = match &tag {
                Some(_) => None,
                None => Some((
                    <spec::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    typed::<spec::list::v0_1::Payload>(payload.clone())?,
                )),
            };
            if let Some(t) = &tag {
                payload["tag"] = json!(t);
            }
            let payload = typed::<spec::list::v0_2::Payload>(payload)?;
            let type_uri = <spec::list::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v = read_v0_2(client, type_uri, payload, fallback, &key).await?;
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
            let payload = typed::<spec::get::v0_2::Payload>(json!({ "roomId": room }))?;
            let type_uri = <spec::get::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let fallback = (
                <spec::get::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                typed::<spec::get::v0_1::Payload>(json!({ "roomId": room }))?,
            );
            let v = read_v0_2(client, type_uri, payload, Some(fallback), &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            if let Some(state) = v.pointer("/ext/org.openvtc/roomProfile") {
                println!("  {DIM}{}{RESET}", room_profile_state(state));
            }
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
            // 0.2 writes a new label or description into the room as its profile too; a VTC
            // that predates it gets 0.1, which takes the same request.
            let versions = vec![
                (
                    <spec::update::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    typed::<spec::update::v0_2::Payload>(payload.clone())?,
                ),
                (
                    <spec::update::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    payload,
                ),
            ];
            let v = change_at_newest(client, &target.base, versions, &did, &key).await?;
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
                let payload = typed::<spec::members::add::v0_1::Payload>(json!({
                    "roomId": room,
                    "member": member,
                    "actions": acts,
                    "validUntil": until,
                    "reason": reason,
                }))?;
                let type_uri =
                    <spec::members::add::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
                let v = change(client, &target.base, type_uri, payload, &did, &key).await?;
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
                let payload = typed::<spec::members::list::v0_1::Payload>(payload)?;
                let type_uri =
                    <spec::members::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
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
        let ok = typed::<spec::members::add::v0_1::Payload>(json!({
            "roomId": "did:key:z6MkRoom", "member": "did:key:z6MkMember",
            "actions": ["read"], "validUntil": "2027-10-01T00:00:00Z", "reason": "r",
        }));
        assert!(ok.is_ok());
        let admin = typed::<spec::members::add::v0_1::Payload>(json!({
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
