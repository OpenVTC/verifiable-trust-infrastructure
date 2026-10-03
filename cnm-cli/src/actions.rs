//! `cnm actions {list,show,cancel}` — the community's administrator action
//! list (`docs/05-design-notes/vtc-action-list.md`).
//!
//! An operation that needs other administrators' approval is parked by the VTC
//! as an action and completes itself on the approval that reaches its
//! threshold (VTI-APV-017). `cnm actions list` shows what waits for you, what
//! you asked for, and what closed; `cnm consent approve --action <id>` decides
//! one. Every summary is re-derived from the payload that will run before it
//! is shown (`vtc_client::actions::verify_action`).

use std::io::IsTerminal;

use clap::Subcommand;
use serde_json::Value;
use vta_cli_common::render::{BOLD, DIM, GREEN, RED, RESET, YELLOW, bin_name};
use vta_sdk::session::TransportChoice;
use vtc_client::actions::VerifiedAction;

use crate::vtc::{self, VtcTarget};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum ActionsCommands {
    /// List actions: those waiting for your approval (the default), those you
    /// asked for, history, or all you may see.
    List {
        #[arg(long, value_enum, default_value = "waiting")]
        view: ListView,
    },
    /// Show one action, its summary re-derived from what will run.
    Show { action_id: String },
    /// Withdraw an open action you asked for.
    Cancel {
        action_id: String,
        /// A note shown to the approvers and kept in the audit record.
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ListView {
    Waiting,
    Requested,
    History,
    All,
}

impl ListView {
    fn wire(self) -> &'static str {
        match self {
            Self::Waiting => "waitingForMe",
            Self::Requested => "requestedByMe",
            Self::History => "history",
            Self::All => "all",
        }
    }
}

pub async fn run(
    command: ActionsCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult<()> {
    let vtc = vtc::connect_for_tasks(keyring_key, target, transport).await?;
    let result = async {
        match command {
            ActionsCommands::List { view } => {
                let mut cursor: Option<String> = None;
                let mut first = true;
                loop {
                    let page = vtc
                        .client
                        .list_actions(view.wire(), cursor.as_deref())
                        .await?;
                    if first {
                        println!(
                            "{BOLD}{} waiting for you{RESET}, {} requested by you",
                            page["counts"]["waitingForMe"], page["counts"]["requestedByMe"]
                        );
                        first = false;
                    }
                    for action in page["actions"].as_array().into_iter().flatten() {
                        print_line(action);
                    }
                    match page["nextCursor"].as_str() {
                        Some(next) => cursor = Some(next.to_string()),
                        None => break,
                    }
                }
                Ok(())
            }
            ActionsCommands::Show { action_id } => {
                let verified = verified(vtc.client.show_action(&action_id).await?)?;
                render(&verified);
                Ok(())
            }
            ActionsCommands::Cancel { action_id, reason } => {
                let action = vtc
                    .client
                    .cancel_action(&action_id, reason.as_deref())
                    .await?;
                println!(
                    "{GREEN}✓ withdrawn{RESET} — {} is {}",
                    action_id, action["status"]
                );
                Ok(())
            }
        }
    }
    .await;
    vtc.client.shutdown().await;
    result
}

fn print_line(action: &Value) {
    let title = vtc_client::actions::verify_action(action)
        .map(|v| v.title)
        .unwrap_or_else(|e| format!("{RED}summary refused: {e}{RESET}"));
    let s = |k: &str| action[k].as_str().unwrap_or("?").to_string();
    println!(
        "  {}  {}  {title}  {DIM}{} · {} of {} · expires {}{RESET}",
        s("actionId"),
        s("status"),
        s("requester"),
        action["approvals"].as_array().map(Vec::len).unwrap_or(0),
        action["threshold"],
        s("expiresAt"),
    );
}

/// `action`, its summary re-derived from its payload — or refused.
pub fn verified(action: Value) -> CliResult<VerifiedAction> {
    vtc_client::actions::verify_action(&action).map_err(|e| {
        format!(
            "{RED}refusing this action{RESET}: {e}. What it says is not what would run; do \
             not approve it."
        )
        .into()
    })
}

/// The six-hex-digit code an action's digest gives — the same on the
/// requester's screen, the console's card, and here.
pub fn match_code(v: &VerifiedAction) -> Option<String> {
    vta_sdk::task_consent::match_code(v.action["payloadDigest"].as_str()?).ok()
}

pub fn render(v: &VerifiedAction) {
    let a = &v.action;
    println!();
    println!("  {BOLD}{}{RESET}", v.title);
    if let Some(effect) = &v.effect {
        println!("  {YELLOW}! {effect}{RESET}");
    }
    for (name, value) in &v.fields {
        println!("  {DIM}{name}:{RESET} {value}");
    }
    println!(
        "  {DIM}action:   {RESET} {}",
        a["actionId"].as_str().unwrap_or("?")
    );
    println!(
        "  {DIM}task:     {RESET} {}",
        a["typeUri"].as_str().unwrap_or("?")
    );
    println!(
        "  {DIM}requester:{RESET} {}",
        a["requester"].as_str().unwrap_or("?")
    );
    println!(
        "  {DIM}status:   {RESET} {}{}",
        a["status"].as_str().unwrap_or("?"),
        a["closedReason"]
            .as_str()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );
    println!(
        "  {DIM}approvals:{RESET} {} of {}",
        a["approvals"].as_array().map(Vec::len).unwrap_or(0),
        a["threshold"]
    );
    if let Some(n) = a["requesterOpenActions"].as_u64() {
        println!("  {DIM}requester has {n} open action(s){RESET}");
    }
    if a["ext"]["org.openvtc"]["burst"] == true {
        println!(
            "  {RED}! this requester raised {} actions in the last 10 minutes{RESET}",
            a["ext"]["org.openvtc"]["requesterRecentActions"]
        );
    }
    if let Some(m) = a["ext"]["org.openvtc"]["closedMessage"].as_str() {
        println!("  {DIM}closed:   {RESET} {m}");
    }
    if let Some(e) = a["expiresAt"].as_str() {
        println!("  {DIM}expires:  {RESET} {e}");
    }
    if let Some(code) = match_code(v) {
        println!();
        println!("      {BOLD}code: {code}{RESET}");
    }
    println!();
}

/// Approval proceeds only on a code the operator compared.
pub fn confirm_match_code(v: &VerifiedAction, given: Option<&str>) -> CliResult<()> {
    let expected = match_code(v).ok_or("the action carries no digest to compare")?;
    let typed = match given {
        Some(code) => code.to_string(),
        None if std::io::stderr().is_terminal() => dialoguer::Input::<String>::new()
            .with_prompt("Type the code shown beside this action on the requester's screen")
            .interact_text()?,
        None => {
            return Err(
                "approving needs the action's match code: pass `--match-code <code>` after \
                 comparing it with the code above"
                    .into(),
            );
        }
    };
    if !typed.trim().eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "{RED}the code does not match{RESET} — nothing was approved. Deny it with `{} \
             consent deny --action <id>` if you do not recognise it.",
            bin_name()
        )
        .into());
    }
    Ok(())
}

pub fn report_decision(r: &vtc_client::actions::decision_v0_2::Response) {
    use vtc_client::actions::decision_v0_2::ResponseStatus;
    let ext = r
        .ext
        .as_ref()
        .and_then(|e| serde_json::to_value(e).ok())
        .unwrap_or_default();
    match r.status {
        ResponseStatus::Granted if ext["org.openvtc"]["actionStatus"] == "failed" => println!(
            "{YELLOW}✓ approved — but the operation was refused when it ran{RESET}: {}",
            ext["org.openvtc"]["closedMessage"]
                .as_str()
                .unwrap_or("see `cnm actions show`")
        ),
        ResponseStatus::Granted => {
            println!(
                "{GREEN}✓ approved{RESET} — that was the last approval needed; the operation ran."
            )
        }
        ResponseStatus::Pending => println!(
            "{GREEN}✓ approval recorded{RESET} — {} of {} so far.",
            r.approvals.unwrap_or(0),
            r.needed
                .map(|n| n.get().to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        ResponseStatus::Denied => {
            println!("{YELLOW}✗ declined{RESET} — the action is closed for everyone.")
        }
        other => println!("the VTC answered `{other}`"),
    }
}
