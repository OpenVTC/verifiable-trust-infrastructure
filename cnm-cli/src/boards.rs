//! `cnm boards …` — running the community's boards (`vtc/boards/*`, VTI-BRD-001 – 080).
//!
//! - `init` writes a starting board (a JSON file, the `vtc/boards/create` payload) offline:
//!   an unconference's "would you attend?" election template, proposals open for a week, voting
//!   overlapping its end. Edit it, then `create` it.
//! - `create` takes `vtc.boards.manage` **and** `vtc.elections.manage`: the template decides
//!   every election the board's facilitators will open (VTI-BRD-002).
//! - `list`, `show` and `notes` read; `update`, `close` and `archive` change a board.
//! - `decide` accepts an idea (opening its election from the template), declines, merges or
//!   reopens it; `select` records a facilitator's choice once its election is tallied; `hide`
//!   and `unhide` moderate notes.
//!
//! Sent as `cnm access` sends ([`vtc_target::connect_for_tasks`]), signed with this profile's
//! own key — a facilitator's acts never take a member's portal or wallet key (VTI-BRD-051).
//! Members propose, note and vote with `pnm boards` and `pnm elections`.

use std::path::PathBuf;

use chrono::{Duration, DurationRound, Utc};
use clap::Subcommand;
use serde_json::{Value, json};
use vta_cli_common::render::{
    BOLD, DIM, GREEN, RESET, YELLOW, bin_name, is_json_output, print_json,
};
use vta_sdk::session::TransportChoice;
use vtc_client::VtcError;
use vtc_client::boards::{self as wire, task};

use crate::vtc::{self as vtc_target, Connected, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum BoardsCommands {
    /// Write a starting board, offline: nothing is sent. Edit it, then `create` it.
    Init {
        /// The voting service every idea's election is registered with: one of this
        /// community's trusted ballot boxes (`cnm elections ballot-boxes`).
        #[arg(long)]
        ballot_box: String,
        #[arg(long, default_value = "Unconference")]
        title: String,
        /// Put the board to one group's members instead of every member.
        #[arg(long)]
        group: Option<String>,
        /// Where to write it. Default: standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Replace `--out` if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Create a board from a JSON file (the `vtc/boards/create` payload).
    Create { board: PathBuf },
    /// List the boards.
    List {
        /// Only boards in this status: open, closed or archived.
        #[arg(long)]
        status: Option<String>,
    },
    /// One board and every idea on it, with where each stands.
    Show {
        board_id: String,
        /// Only ideas in these states. Repeat for several.
        #[arg(long = "state")]
        states: Vec<String>,
    },
    /// Change a board from a JSON file of the members to change (`vtc/boards/update`, without
    /// `boardId`). Changing `template` also takes `vtc.elections.manage`.
    Update { board_id: String, changes: PathBuf },
    /// Close a board to new ideas and notes, and end its voting: each idea's election open for
    /// voting is closed early, so its count is final; one not yet open is cancelled
    /// (VTI-BRD-006). Facilitators still decide and select.
    Close { board_id: String },
    /// Archive a closed board: no change at all after this.
    Archive { board_id: String },
    /// Delete a closed board whose voting has ended: its ideas, notes and each election's
    /// content go; each election keeps only a tombstone (its identifier, manifest digest and the
    /// board heads the community kept) for the community's `[boards] tombstone_retention`.
    /// Takes vtc.boards.manage unqualified and a passkey gesture bound to the deletion.
    Delete {
        board_id: String,
        /// Why, recorded with the deletion in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Accept, decline, merge or reopen a proposed idea. Accepting opens its election.
    Decide {
        idea_id: String,
        /// accept, decline, merge or reopen.
        decision: String,
        /// Required to decline; shown to the board's audience.
        #[arg(long)]
        reason: Option<String>,
        /// For merge: the idea this one is folded into.
        #[arg(long)]
        into: Option<String>,
    },
    /// Record whether a tallied idea is selected, optionally into a timetable slot.
    Select {
        idea_id: String,
        /// selected or not-selected.
        decision: String,
        /// The timetable slot a selected idea fills (a slot id from `show`).
        #[arg(long)]
        slot: Option<String>,
        /// The decision departs from the board's selection rule; needs --reason.
        #[arg(long, requires = "reason")]
        departs_from_rule: bool,
        /// Why; required with --departs-from-rule, recorded with the decision.
        #[arg(long)]
        reason: Option<String>,
    },
    /// The notes on a board (with hidden and withdrawn ones' text), or on one idea.
    Notes {
        board_id: String,
        #[arg(long)]
        idea: Option<String>,
    },
    /// Hide a note, with a reason shown in its place.
    Hide {
        note_id: String,
        #[arg(long)]
        reason: String,
    },
    /// Show a hidden note again.
    Unhide { note_id: String },
}

/// A starting board: proposals from the next whole hour for a week, voting from two days
/// before proposals close until two days after, a "would you attend?" election template.
#[must_use]
pub fn starter_board(ballot_box: &str, title: &str, group: Option<&str>) -> Value {
    let start = Utc::now()
        .duration_trunc(Duration::hours(1))
        .unwrap_or_else(|_| Utc::now())
        + Duration::hours(1);
    let at = |d: Duration| (start + d).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let audience = match group {
        Some(g) => json!({ "kind": "group", "groupId": g }),
        None => json!({ "kind": "members" }),
    };
    json!({
        "title": title,
        "description": "Propose a session. The ones the most members would attend fill the timetable.",
        "audience": audience,
        "proposals": { "opensAt": at(Duration::zero()), "closesAt": at(Duration::days(7)) },
        "voting": { "opensAt": at(Duration::days(5)), "closesAt": at(Duration::days(9)) },
        "formats": ["Discussion", "Talk", "Workshop", "Demo"],
        "maxIdeasPerMember": 3,
        "selectionRule": "The sessions the most members would attend.",
        "template": {
            "questions": [{
                "key": "attend",
                "type": "choice",
                "text": "Would you attend this session?",
                "options": [
                    { "key": "yes", "label": "Yes, I'd attend" },
                    { "key": "no", "label": "Not for me" }
                ],
                "minSelections": 1,
                "maxSelections": 1,
                "optional": false
            }],
            "secrecy": "open",
            "revote": "replace",
            "board": { "visibility": "public", "auditors": [] },
            "ballotBox": ballot_box,
            "allowEarlyClose": true,
            "resultsBeforeClose": false,
            "textReleaseThreshold": 10
        }
    })
}

fn read_json(path: &PathBuf) -> CliResult<Value> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    Ok(serde_json::from_str(&raw).map_err(|e| format!("{} is not JSON: {e}", path.display()))?)
}

/// `init`, offline.
pub fn run_init(command: BoardsCommands) -> CliResult {
    let BoardsCommands::Init {
        ballot_box,
        title,
        group,
        out,
        force,
    } = command
    else {
        unreachable!("only `init` is answered offline");
    };
    let board = starter_board(&ballot_box, &title, group.as_deref());
    wire::checked(task::CREATE, board.clone())?;
    let text = serde_json::to_string_pretty(&board)? + "\n";
    match out {
        None => print!("{text}"),
        Some(path) => {
            if path.exists() && !force {
                return Err(
                    format!("{} exists: pass --force to replace it", path.display()).into(),
                );
            }
            std::fs::write(&path, text)?;
            eprintln!(
                "{GREEN}wrote{RESET} {} — edit it, then `{} boards create {}`",
                path.display(),
                bin_name(),
                path.display()
            );
        }
    }
    Ok(())
}

pub async fn run(
    command: BoardsCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    if matches!(command, BoardsCommands::Init { .. }) {
        return run_init(command);
    }
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_command(command, &vtc, keyring_key).await;
    vtc.client.shutdown().await;
    outcome
}

// ── Rendering ───────────────────────────────────────────────────────────────

fn author(a: &Value) -> String {
    if a["formerMember"] == json!(true) {
        "a former member".into()
    } else {
        a["name"].as_str().unwrap_or("a member").to_string()
    }
}

/// Where an idea stands, for its facilitator.
fn standing(i: &Value) -> String {
    let state = i["state"].as_str().unwrap_or("");
    if state == "proposed" {
        if let Some(code) = i["opening"]["refusal"]["code"].as_str() {
            return format!("{YELLOW}its election was refused ({code}){RESET} — still proposed");
        }
        if !i["opening"].is_null() {
            return "accepted — waiting for the ballot box to register its election".into();
        }
        return format!("{YELLOW}proposed — waiting for you{RESET}");
    }
    let e = &i["election"];
    let result = &e["result"];
    if !result.is_null() {
        let counted = result["ballotsCounted"].as_u64().unwrap_or(0);
        let choice = &result["questions"][0]["choice"];
        let total: u64 = choice
            .as_object()
            .map(|m| m.values().filter_map(Value::as_u64).sum())
            .unwrap_or(0);
        let share = match choice["yes"].as_u64() {
            Some(y) if total > 0 => format!(", {}% yes", y * 100 / total),
            _ => String::new(),
        };
        let certified = if e["certified"] == json!(true) {
            ", certified"
        } else {
            ", not certified"
        };
        let what = match state {
            "open" => format!("{YELLOW}tallied — select it or not{RESET}"),
            "selected" => format!("{GREEN}selected{RESET}"),
            _ => "not selected".into(),
        };
        return format!("{what} ({counted} counted{share}{certified})");
    }
    match (state, e["ballotsOnBoard"].as_u64()) {
        ("open", Some(n)) => format!("open — {n} ballots on the board"),
        ("open", None) => "open for votes".into(),
        ("declined", _) => format!(
            "declined: {}",
            i["decision"]["reason"].as_str().unwrap_or("")
        ),
        ("merged", _) => format!(
            "merged into {}",
            i["decision"]["mergedInto"].as_str().unwrap_or("")
        ),
        (s, _) => s.to_string(),
    }
}

fn print_idea(i: &Value) {
    println!(
        "{BOLD}{}{RESET}  {DIM}{}{RESET}",
        i["title"].as_str().unwrap_or(""),
        i["ideaId"].as_str().unwrap_or("")
    );
    println!("  {}", standing(i));
    let mut meta = vec![author(&i["proposer"])];
    for k in ["format", "topic"] {
        if let Some(v) = i[k].as_str() {
            meta.push(v.to_string());
        }
    }
    meta.push(format!("{} notes", i["noteCount"].as_u64().unwrap_or(0)));
    if let Some(slot) = i["decision"]["slotId"].as_str() {
        meta.push(format!("slot {slot}"));
    }
    println!("  {DIM}{}{RESET}", meta.join(" · "));
}

/// The refusal, with the fix where the code names one.
fn refusal(vtc: &Connected, err: VtcError, subject: &str) -> Box<dyn std::error::Error> {
    let text = err.to_string();
    let bin = bin_name();
    let fix = if text.contains("ballotBoxNotTrusted") {
        Some(format!(
            "The template's ballot box is not one this community trusts: pick one from `{bin} \
             elections ballot-boxes`."
        ))
    } else if text.contains("templateInvalid") {
        Some(format!(
            "The election template is not one the community would accept. If this VTC is built \
             without `voting`, no board can be created; otherwise check the template with `{bin} \
             elections manifest check` on a manifest made from it."
        ))
    } else if text.contains("scheduleInvalid") {
        Some(
            "Each window must close after it opens, voting must open after proposals open, and \
             voting must close after proposals close."
                .into(),
        )
    } else if text.contains("notClosed") {
        Some(format!(
            "{subject} is open. Close it first, which ends its voting: `{bin} boards close {subject}`."
        ))
    } else if text.contains("electionsRunning") {
        Some(format!(
            "An idea on {subject} still has an election running — one that cannot close early, or \
             one the ballot box has not answered yet. See which with `{bin} boards show {subject}`; \
             wait for it to close, or cancel it with `{bin} elections cancel <election-id> --reason …`."
        ))
    } else if text.contains("stepUpRequest") || text.contains("passkey gesture") {
        Some(format!(
            "The VTC needs a passkey gesture from {} bound to this request: approve it in the \
             admin console, then run the same command again.",
            vtc.client_did
        ))
    } else if text.contains("ownIdea") {
        Some(format!(
            "You proposed {subject}, and the board has another facilitator: they decide it."
        ))
    } else if text.contains("notTallied") {
        Some(format!(
            "{subject}'s election has no verified result yet: it is verified once voting closes and \
             the ballot box publishes its result. Try again later."
        ))
    } else if text.contains("reasonRequired") {
        Some("This needs --reason: the board's audience is shown it.".into())
    } else if text.contains("permissionDenied") || text.contains("Forbidden") {
        Some(format!(
            "{} does not facilitate this board: that takes vtc.boards.manage (for every board, or \
             qualified board:<boardId>); creating a board, or changing its template, also takes \
             vtc.elections.manage.",
            vtc.client_did
        ))
    } else {
        None
    };
    match fix {
        Some(f) => format!("{f}\n({text})").into(),
        None => format!("the VTC refused {}: {text}", vtc.client_did).into(),
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

/// Move a board forward to `status`: `closed` takes no new ideas or notes, `archived` no change
/// at all (VTI-BRD-005).
async fn set_status(
    vtc: &Connected,
    key: &vtc_client::HolderKey,
    board_id: &str,
    status: &str,
) -> CliResult {
    let updated = vtc
        .client
        .boards_update(json!({ "boardId": board_id, "status": status }), key)
        .await
        .map_err(|e| refusal(vtc, e, board_id))?;
    if is_json_output() {
        return Ok(print_json(&updated)?);
    }
    println!("{GREEN}{status}{RESET} {BOLD}{board_id}{RESET}");
    if let Some(c) = serde_json::to_value(&updated)?.get("closing") {
        println!(
            "  voting ended: {} election(s) closed early, their counts final; {} cancelled",
            c["closedEarly"], c["cancelled"]
        );
        let running: Vec<&str> = c["runningToClose"]
            .as_array()
            .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        if !running.is_empty() {
            println!(
                "  {YELLOW}still running{RESET} (cannot close early, close when their manifest says): {}",
                running.join(", ")
            );
        }
    }
    Ok(())
}

async fn run_command(command: BoardsCommands, vtc: &Connected, keyring_key: &str) -> CliResult {
    let key = crate::access::signing_key(keyring_key)?;
    let c = &vtc.client;
    match command {
        BoardsCommands::Init { .. } => unreachable!("`init` is answered in `run`, offline"),
        BoardsCommands::Create { board } => {
            let body = read_json(&board)?;
            let created = c
                .boards_create(body, &key)
                .await
                .map_err(|e| refusal(vtc, e, ""))?;
            if is_json_output() {
                return Ok(print_json(&created)?);
            }
            let v = serde_json::to_value(&created)?;
            println!(
                "{GREEN}created{RESET} {BOLD}{}{RESET} — {}",
                v["board"]["boardId"].as_str().unwrap_or(""),
                v["board"]["title"].as_str().unwrap_or("")
            );
            Ok(())
        }
        BoardsCommands::List { status } => {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let page = c
                    .boards_list(status.as_deref(), cursor.as_deref(), Some(200), &key)
                    .await
                    .map_err(|e| refusal(vtc, e, ""))?;
                let v = serde_json::to_value(&page)?;
                all.extend(v["boards"].as_array().cloned().unwrap_or_default());
                match v["nextCursor"].as_str() {
                    Some(n) => cursor = Some(n.to_string()),
                    None => break,
                }
            }
            if is_json_output() {
                return Ok(print_json(&all)?);
            }
            if all.is_empty() {
                println!("{DIM}no boards{RESET}");
            }
            for b in &all {
                let counts = &b["ideaCounts"];
                println!(
                    "{BOLD}{}{RESET}  {DIM}{}{RESET}",
                    b["title"].as_str().unwrap_or(""),
                    b["boardId"].as_str().unwrap_or("")
                );
                println!(
                    "  {} · {} proposed · {} open · {} selected · votes close {}",
                    b["status"].as_str().unwrap_or(""),
                    counts["proposed"].as_u64().unwrap_or(0),
                    counts["open"].as_u64().unwrap_or(0),
                    counts["selected"].as_u64().unwrap_or(0),
                    b["voting"]["closesAt"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        BoardsCommands::Show { board_id, states } => {
            let states: Vec<&str> = states.iter().map(String::as_str).collect();
            let mut ideas = Vec::new();
            let mut board;
            let mut cursor: Option<String> = None;
            loop {
                let page = c
                    .boards_show(&board_id, &states, cursor.as_deref(), Some(200), &key)
                    .await
                    .map_err(|e| refusal(vtc, e, &board_id))?;
                let v = serde_json::to_value(&page)?;
                board = v["board"].clone();
                ideas.extend(v["ideas"].as_array().cloned().unwrap_or_default());
                match v["nextCursor"].as_str() {
                    Some(n) => cursor = Some(n.to_string()),
                    None => break,
                }
            }
            if is_json_output() {
                return Ok(print_json(&json!({ "board": board, "ideas": ideas }))?);
            }
            println!(
                "{BOLD}{}{RESET}  {}  {DIM}{board_id}{RESET}",
                board["title"].as_str().unwrap_or(""),
                board["status"].as_str().unwrap_or("")
            );
            println!(
                "  proposals {} → {} · voting {} → {}",
                board["proposals"]["opensAt"].as_str().unwrap_or(""),
                board["proposals"]["closesAt"].as_str().unwrap_or(""),
                board["voting"]["opensAt"].as_str().unwrap_or(""),
                board["voting"]["closesAt"].as_str().unwrap_or("")
            );
            if let Some(r) = board["selectionRule"].as_str() {
                println!("  {DIM}selection rule: {r}{RESET}");
            }
            for s in board["timetable"].as_array().cloned().unwrap_or_default() {
                println!(
                    "  {DIM}slot {} — {} {}{RESET}",
                    s["slotId"].as_str().unwrap_or(""),
                    s["label"].as_str().unwrap_or(""),
                    s["startsAt"].as_str().unwrap_or("")
                );
            }
            println!();
            if ideas.is_empty() {
                println!("{DIM}no ideas yet{RESET}");
            }
            for i in &ideas {
                print_idea(i);
            }
            Ok(())
        }
        BoardsCommands::Update { board_id, changes } => {
            let mut body = read_json(&changes)?;
            let obj = body
                .as_object_mut()
                .ok_or("the changes must be a JSON object")?;
            obj.insert("boardId".into(), json!(board_id));
            let updated = c
                .boards_update(body, &key)
                .await
                .map_err(|e| refusal(vtc, e, &board_id))?;
            if is_json_output() {
                return Ok(print_json(&updated)?);
            }
            println!("{GREEN}updated{RESET} {BOLD}{board_id}{RESET}");
            Ok(())
        }
        BoardsCommands::Close { board_id } => set_status(vtc, &key, &board_id, "closed").await,
        BoardsCommands::Archive { board_id } => set_status(vtc, &key, &board_id, "archived").await,
        BoardsCommands::Delete { board_id, reason } => {
            let out = c
                .boards_delete(&board_id, &reason, &key)
                .await
                .map_err(|e| refusal(vtc, e, &board_id))?;
            if is_json_output() {
                return Ok(print_json(&out)?);
            }
            let v = serde_json::to_value(&out)?;
            println!(
                "{GREEN}deleted{RESET} {BOLD}{board_id}{RESET}: {} idea(s), {} note(s), {} election(s)",
                v["ideasRemoved"], v["notesRemoved"], v["electionsRemoved"]
            );
            match (
                v["tombstones"]["kept"].as_u64(),
                v["tombstones"]["removeAt"].as_str(),
            ) {
                (Some(0) | None, _) => {
                    println!("  no tombstone kept: nothing of its elections remains")
                }
                (Some(n), Some(at)) => println!(
                    "  {n} tombstone(s) kept until {at}: each election's identifier, manifest digest \
                     and kept board heads, so receipts stay checkable until then"
                ),
                (Some(n), None) => println!("  {n} tombstone(s) kept for ever"),
            }
            Ok(())
        }
        BoardsCommands::Decide {
            idea_id,
            decision,
            reason,
            into,
        } => {
            let decided = c
                .boards_decide(
                    &idea_id,
                    &decision,
                    reason.as_deref(),
                    into.as_deref(),
                    &key,
                )
                .await
                .map_err(|e| refusal(vtc, e, &idea_id))?;
            if is_json_output() {
                return Ok(print_json(&decided)?);
            }
            let v = serde_json::to_value(&decided)?;
            print_idea(&v["idea"]);
            Ok(())
        }
        BoardsCommands::Select {
            idea_id,
            decision,
            slot,
            departs_from_rule,
            reason,
        } => {
            let decision = match decision.as_str() {
                "selected" => "selected",
                "not-selected" | "notSelected" => "notSelected",
                other => {
                    return Err(format!("{other}: say `selected` or `not-selected`").into());
                }
            };
            let selected = c
                .boards_select(
                    &idea_id,
                    decision,
                    slot.as_deref(),
                    departs_from_rule,
                    reason.as_deref(),
                    &key,
                )
                .await
                .map_err(|e| refusal(vtc, e, &idea_id))?;
            if is_json_output() {
                return Ok(print_json(&selected)?);
            }
            let v = serde_json::to_value(&selected)?;
            print_idea(&v["idea"]);
            Ok(())
        }
        BoardsCommands::Notes { board_id, idea } => {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            let scope = if idea.is_none() { Some("all") } else { None };
            loop {
                let page = c
                    .boards_notes(
                        &board_id,
                        idea.as_deref(),
                        scope,
                        cursor.as_deref(),
                        Some(200),
                        &key,
                    )
                    .await
                    .map_err(|e| refusal(vtc, e, &board_id))?;
                let v = serde_json::to_value(&page)?;
                all.extend(v["notes"].as_array().cloned().unwrap_or_default());
                match v["nextCursor"].as_str() {
                    Some(n) => cursor = Some(n.to_string()),
                    None => break,
                }
            }
            if is_json_output() {
                return Ok(print_json(&all)?);
            }
            if all.is_empty() {
                println!("{DIM}no notes{RESET}");
            }
            for n in &all {
                let state = n["state"].as_str().unwrap_or("");
                let mark = match state {
                    "hidden" => format!(
                        "{YELLOW}[hidden: {}]{RESET} ",
                        n["hiddenReason"].as_str().unwrap_or("")
                    ),
                    "withdrawn" => format!("{DIM}[withdrawn]{RESET} "),
                    _ => String::new(),
                };
                println!("  {mark}{}", n["text"].as_str().unwrap_or(""));
                println!(
                    "    {DIM}{} · on {} · {}{RESET}",
                    author(&n["author"]),
                    n["ideaId"].as_str().unwrap_or("the board"),
                    n["noteId"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        BoardsCommands::Hide { note_id, reason } => {
            let hidden = c
                .boards_hide_note(&note_id, true, Some(&reason), &key)
                .await
                .map_err(|e| refusal(vtc, e, &note_id))?;
            if is_json_output() {
                return Ok(print_json(&hidden)?);
            }
            println!("{GREEN}hidden{RESET} {BOLD}{note_id}{RESET}");
            Ok(())
        }
        BoardsCommands::Unhide { note_id } => {
            let shown = c
                .boards_hide_note(&note_id, false, None, &key)
                .await
                .map_err(|e| refusal(vtc, e, &note_id))?;
            if is_json_output() {
                return Ok(print_json(&shown)?);
            }
            println!("{GREEN}shown again{RESET} {BOLD}{note_id}{RESET}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOX: &str = "did:webvh:QmBox:example.org:ballot-box";

    /// `init` writes a board an operator can create as written: it reads
    /// against `vtc/boards/create`'s own schema, with no edits.
    #[test]
    fn the_starter_board_is_a_valid_create_for_members() {
        let board = starter_board(BOX, "Unconference", None);
        wire::checked(task::CREATE, board).expect("the starter board reads against the schema");
    }

    #[test]
    fn the_starter_board_is_a_valid_create_for_a_group() {
        let board = starter_board(BOX, "Unconference", Some("grp_0123456789abcdef"));
        assert_eq!(board["audience"]["kind"], "group");
        wire::checked(task::CREATE, board).expect("a group board reads against the schema");
    }
}
