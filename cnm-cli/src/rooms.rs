//! `cnm rooms …` — the data rooms the community itself **owns**
//! (`vtc/rooms/community/*`, `docs/05-design-notes/data-rooms-files.md` §8.4).
//!
//! The community is the owner and its own VTA holds each room's keys: this command never
//! signs as a room, holds a room key or sees a credential. It signs a request as this
//! profile's administrator identity, and the VTC has its VTA do the rest — mint the room's
//! identity, found its group, issue a member's credentials. A change (`create`,
//! `members add`, `members remove`) takes a passkey gesture bound to that one request,
//! answered in a browser as `cnm git` changes are; reads take none. Every one needs
//! `vtc.rooms.manage` on this profile's entry.
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
    /// Remove a member, or withdraw an open offer. On a sealed room the room advances to an
    /// epoch sealed to everyone else.
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

/// A change: through the passkey gesture it asks for. A refusal is rewritten with its fix.
async fn change(
    client: &VtcClient,
    base: &str,
    type_uri: &str,
    payload: Value,
    did: &str,
    key: &HolderKey,
) -> CliResult<Value> {
    send_change(client, base, type_uri, &payload, did, key)
        .await
        .map_err(|e| {
            let text = e.to_string();
            format!("{text}{}", hint(refused_code(&text).unwrap_or_default())).into()
        })
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
    println!(
        "{BOLD}{}{RESET} — {} · {} · epoch {} · {}",
        terminal_safe(room["label"].as_str().unwrap_or_default()),
        terminal_safe(r["roomId"].as_str().unwrap_or_default()),
        r["visibility"].as_str().unwrap_or_default(),
        r["epoch"],
        r["lifecycle"].as_str().unwrap_or_default(),
    );
    println!(
        "  {DIM}admitted {} · offered {} · storage {} · the community's authority until {}{RESET}",
        room["admitted"],
        room["offered"],
        terminal_safe(room["storageConfig"].as_str().unwrap_or("-")),
        room["ownerAuthorityValidUntil"].as_str().unwrap_or("-"),
    );
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
            let payload = typed::<spec::create::v0_1::Payload>(payload)?;
            let type_uri = <spec::create::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v = change(client, &target.base, type_uri, payload, &did, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
            println!(
                "The community's VTA holds the room's keys. Offer members admission with \
                 `{} rooms members add {} --member <did> --action read --valid-for 90d --reason …`.",
                bin_name(),
                terminal_safe(v["room"]["room"]["roomId"].as_str().unwrap_or_default()),
            );
            Ok(())
        }
        RoomsCommands::List { limit, cursor } => {
            let mut payload = json!({});
            if let Some(l) = limit {
                payload["limit"] = json!(l);
            }
            if let Some(c) = cursor {
                payload["cursor"] = json!(c);
            }
            let payload = typed::<spec::list::v0_1::Payload>(payload)?;
            let type_uri = <spec::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
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
            let items = v["items"].as_array().cloned().unwrap_or_default();
            if items.is_empty() {
                println!("The community owns no rooms.");
            }
            for room in &items {
                print_room(room);
            }
            print_next(&v);
            Ok(())
        }
        RoomsCommands::Get { room } => {
            let payload = typed::<spec::get::v0_1::Payload>(json!({ "roomId": room }))?;
            let type_uri = <spec::get::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let v = read(client, type_uri, payload, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_room(&v["room"]);
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
                let payload = typed::<spec::members::remove::v0_1::Payload>(json!({
                    "roomId": room,
                    "member": member,
                    "reason": reason,
                }))?;
                let type_uri =
                    <spec::members::remove::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
                let v = change(client, &target.base, type_uri, payload, &did, &key).await?;
                if is_json_output() {
                    return Ok(print_json(&v)?);
                }
                print_member(&v["member"]);
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

    #[test]
    fn a_refusal_names_its_fix() {
        assert!(hint("permissionDenied").contains("vtc.rooms.manage"));
        assert!(hint("vtc/rooms/community/create:noKeyHolder").contains("[rooms.community]"));
        assert!(hint("something-else").is_empty());
        assert_eq!(
            refused_code("the community refused it (permissionDenied): no"),
            Some("permissionDenied")
        );
        assert_eq!(refused_code("the step-up was not completed"), None);
    }
}
