//! Rooms this profile works with, so `pnm rooms …` stops re-asking (#2590).
//!
//! A room's verbs each need the same three or four long values — the room's
//! DID, its host's URL and DID, the room's signing key id — copied from
//! scrollback. They are kept per room in `rooms.toml` beside `config.toml`:
//!
//! - written where they become known: `rooms owner register` (room → host
//!   DID), `rooms offers accept` (room → the community as host), `rooms keys
//!   welcome` (the room), and `pnm rooms use <room> [--host …] [--host-did …]
//!   [--signing-key …]`, which also makes it the default room;
//! - read at parse time as clap **defaults**: a flag given on the command line
//!   always wins, a stored value fills one that is absent, and a flag with no
//!   stored value is still required exactly as before. `--help` shows the
//!   default in force. The room is the one `--room` names, else the default.
//!
//! Nothing here is a secret: a signing key *id*, never key material.

use std::collections::BTreeMap;
use std::ffi::OsString;

use clap::{CommandFactory, FromArgMatches};
use serde::{Deserialize, Serialize};

use crate::cli::Cli;

/// What is stored for one room. Every member optional: each is learned at a
/// different step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RoomEntry {
    /// Base URL of the host storing the room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host: Option<String>,
    /// The host's DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host_did: Option<String>,
    /// The room's signing key id (an owner's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signing_key: Option<String>,
}

impl RoomEntry {
    fn merge(&mut self, other: RoomEntry) {
        if other.host.is_some() {
            self.host = other.host;
        }
        if other.host_did.is_some() {
            self.host_did = other.host_did;
        }
        if other.signing_key.is_some() {
            self.signing_key = other.signing_key;
        }
    }
}

/// `rooms.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RoomsProfile {
    /// The room a command means when it names none (`pnm rooms use`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) default_room: Option<String>,
    #[serde(default)]
    pub(crate) rooms: BTreeMap<String, RoomEntry>,
}

fn path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(crate::config::config_dir()?.join("rooms.toml"))
}

pub(crate) fn load() -> Result<RoomsProfile, Box<dyn std::error::Error>> {
    Ok(vta_cli_common::config_file::load_toml(&path()?)?)
}

fn save(p: &RoomsProfile) -> Result<(), Box<dyn std::error::Error>> {
    vta_cli_common::config_file::save_toml_atomic(&path()?, p)
}

/// Record what a step learned about `room`. Never fails the step that called
/// it: the room is joined or registered whether or not the note is written,
/// so a failure is a warning.
pub(crate) fn remember(room: &str, learned: RoomEntry, make_default: bool) {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut p = load()?;
        p.rooms.entry(room.to_string()).or_default().merge(learned);
        if make_default || p.default_room.is_none() {
            p.default_room = Some(room.to_string());
        }
        save(&p)
    })();
    if let Err(e) = result {
        eprintln!("warning: could not remember room {room} for later commands: {e}");
    }
}

/// `pnm rooms use [<room>] [--host] [--host-did] [--signing-key] [--forget]`.
pub(crate) fn cmd_use(
    room: Option<String>,
    entry: RoomEntry,
    forget: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut p = load()?;
    match room {
        None => {
            if vta_cli_common::render::is_json_output() {
                vta_cli_common::render::print_json(&p)?;
                return Ok(());
            }
            if p.rooms.is_empty() {
                println!(
                    "No rooms remembered. `pnm rooms use <room> --host <url> --host-did <did>` \
                     records one."
                );
            }
            for (id, e) in &p.rooms {
                let mark = if p.default_room.as_deref() == Some(id) {
                    "*"
                } else {
                    " "
                };
                println!("{mark} {id}");
                if let Some(h) = &e.host {
                    println!("    host:        {h}");
                }
                if let Some(h) = &e.host_did {
                    println!("    host DID:    {h}");
                }
                if let Some(k) = &e.signing_key {
                    println!("    signing key: {k}");
                }
            }
            Ok(())
        }
        Some(room) if forget => {
            p.rooms.remove(&room);
            if p.default_room.as_deref() == Some(&room) {
                p.default_room = None;
            }
            save(&p)?;
            println!("Forgot room {room}.");
            Ok(())
        }
        Some(room) => {
            p.rooms.entry(room.clone()).or_default().merge(entry);
            p.default_room = Some(room.clone());
            save(&p)?;
            println!("Default room: {room}");
            Ok(())
        }
    }
}

/// The values to fill in, for the room this command line is about.
#[derive(Debug, Default, PartialEq, Eq)]
struct Defaults {
    room: Option<String>,
    entry: RoomEntry,
}

/// Is this a `pnm rooms …` command line, and which room does it name?
/// Returns `None` for any other command.
fn defaults_for(args: &[OsString], p: &RoomsProfile) -> Option<Defaults> {
    let words: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // The first non-flag word is the subcommand. (`--vta x rooms …` puts a
    // value first; a value that happens to be `rooms` is no worse than an
    // unfilled default.)
    if !words.iter().any(|w| w == "rooms") {
        return None;
    }
    let named = words.iter().enumerate().find_map(|(i, w)| {
        if w == "--room" {
            words.get(i + 1).cloned()
        } else {
            w.strip_prefix("--room=").map(str::to_string)
        }
    });
    let room = named.or_else(|| p.default_room.clone());
    let entry = room
        .as_ref()
        .and_then(|r| p.rooms.get(r).cloned())
        .unwrap_or_default();
    Some(Defaults { room, entry })
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

/// Give every `rooms` subcommand's `--room` / `--host` / `--host-did` /
/// `--signing-key` the stored value as its default, recursively.
fn apply(mut cmd: clap::Command, d: &Defaults) -> clap::Command {
    let ids: Vec<String> = cmd
        .get_arguments()
        .map(|a| a.get_id().as_str().to_string())
        .collect();
    for id in ids {
        let value = match id.as_str() {
            "room_id" => d.room.as_deref(),
            "host" => d.entry.host.as_deref(),
            "host_did" => d.entry.host_did.as_deref(),
            "signing_key" => d.entry.signing_key.as_deref(),
            _ => None,
        };
        if let Some(v) = value {
            let v = leak(v);
            cmd = cmd.mut_arg(id, |a| a.default_value(v).required(false));
        }
    }
    let subs: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for s in subs {
        cmd = cmd.mut_subcommand(s, |sc| apply(sc, d));
    }
    cmd
}

/// Parse the command line, with the stored room defaults in force for a
/// `rooms` command. Any other command parses exactly as `Cli::parse` would.
pub(crate) fn parse_cli() -> Cli {
    let args: Vec<OsString> = std::env::args_os().collect();
    if !args.iter().skip(1).any(|a| a == "rooms") {
        return <Cli as clap::Parser>::parse_from(args);
    }
    // An unreadable rooms.toml must not stop every command: say so and parse
    // without defaults. (`config.toml` is the profile that is fatal.)
    let profile = match load() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: room defaults not applied: {e}");
            RoomsProfile::default()
        }
    };
    match defaults_for(&args, &profile) {
        Some(d) if d.room.is_some() => parse_from_with(args, &d),
        _ => <Cli as clap::Parser>::parse_from(args),
    }
}

fn parse_from_with(args: Vec<OsString>, d: &Defaults) -> Cli {
    let cmd = Cli::command().mut_subcommand("rooms", |rooms| apply(rooms, d));
    let matches = cmd.get_matches_from(args);
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Commands, RoomCommands, RoomOwnerCommands};

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn profile() -> RoomsProfile {
        let mut p = RoomsProfile {
            default_room: Some("did:webvh:room-a".into()),
            ..Default::default()
        };
        p.rooms.insert(
            "did:webvh:room-a".into(),
            RoomEntry {
                host: Some("https://host-a".into()),
                host_did: Some("did:webvh:host-a".into()),
                signing_key: Some("key-a".into()),
            },
        );
        p.rooms.insert(
            "did:webvh:room-b".into(),
            RoomEntry {
                host: Some("https://host-b".into()),
                ..Default::default()
            },
        );
        p
    }

    fn parse(v: &[&str]) -> Result<Cli, clap::Error> {
        let args = os(v);
        let d = defaults_for(&args, &profile()).expect("a rooms command");
        let cmd = Cli::command().mut_subcommand("rooms", |rooms| apply(rooms, &d));
        let m = cmd.try_get_matches_from(args)?;
        Cli::from_arg_matches(&m)
    }

    #[test]
    fn the_default_room_fills_every_absent_flag() {
        let cli = parse(&["pnm", "rooms", "get", "k1"]).expect("parses with defaults");
        let Commands::Rooms {
            command:
                RoomCommands::Get {
                    room_id,
                    host,
                    host_did,
                    ..
                },
        } = cli.command
        else {
            panic!("rooms get");
        };
        assert_eq!(room_id, "did:webvh:room-a");
        assert_eq!(host, "https://host-a");
        assert_eq!(host_did.as_deref(), Some("did:webvh:host-a"));
    }

    #[test]
    fn a_flag_on_the_line_wins_and_names_the_room_whose_values_fill_the_rest() {
        let cli =
            parse(&["pnm", "rooms", "get", "k1", "--room", "did:webvh:room-b"]).expect("parses");
        let Commands::Rooms {
            command:
                RoomCommands::Get {
                    room_id,
                    host,
                    host_did,
                    ..
                },
        } = cli.command
        else {
            panic!("rooms get");
        };
        assert_eq!(room_id, "did:webvh:room-b");
        assert_eq!(host, "https://host-b");
        assert_eq!(host_did, None, "room-b has no host DID stored");
    }

    #[test]
    fn the_signing_key_is_filled_for_owner_verbs() {
        let cli = parse(&[
            "pnm",
            "rooms",
            "owner",
            "invite",
            "--member",
            "did:webvh:bob",
            "--out",
            "i.json",
        ])
        .expect("parses");
        let Commands::Rooms {
            command:
                RoomCommands::Owner {
                    command:
                        RoomOwnerCommands::Invite {
                            room_id,
                            signing_key,
                            ..
                        },
                },
        } = cli.command
        else {
            panic!("owner invite");
        };
        assert_eq!(room_id, "did:webvh:room-a");
        assert_eq!(signing_key, "key-a");
    }

    #[test]
    fn a_value_with_nothing_stored_is_still_required() {
        // room-b stores no signing key, so `invite` must still be told one.
        assert!(
            parse(&[
                "pnm",
                "rooms",
                "owner",
                "invite",
                "--room",
                "did:webvh:room-b",
                "--member",
                "did:webvh:bob",
                "--out",
                "i.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn other_commands_are_left_alone() {
        assert_eq!(defaults_for(&os(&["pnm", "acl", "list"]), &profile()), None);
    }

    #[test]
    fn merge_keeps_what_the_new_step_did_not_learn() {
        let mut e = RoomEntry {
            host: Some("h".into()),
            ..Default::default()
        };
        e.merge(RoomEntry {
            host_did: Some("d".into()),
            ..Default::default()
        });
        assert_eq!(e.host.as_deref(), Some("h"));
        assert_eq!(e.host_did.as_deref(), Some("d"));
    }
}
