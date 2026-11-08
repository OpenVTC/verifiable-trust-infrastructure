//! `pnm notifications …` — the notifications the VTA holds for its principal
//! (`vta/notifications/{list,show,dismiss}/0.1`, VTI-NTF-050 – 053), and handing it one a
//! client received for a DID it holds keys of (`vta/notifications/deposit/0.1`, VTI-NTF-054).
//!
//! A notification says only that a thing exists — an election, an invitation — where it is
//! held, and whom it concerns. It is no evidence that anyone may take part (VTI-NTF-004), and
//! listing, reading or dismissing one tells nobody anything. Opening the thing is a separate,
//! deliberate step against its holder (`subject.openWith` sent to `subject.heldBy`), never
//! taken here (VTI-NTF-053).

use serde_json::{Value, json};
use vta_sdk::prelude::*;

use crate::render::{BOLD, CYAN, DIM, GREEN, RESET, is_json_output, print_json};

/// Options for `notifications list`.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub kind: Option<String>,
    pub held_by: Option<String>,
    pub include_dismissed: bool,
    pub include_lapsed: bool,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

fn line(item: &Value) -> String {
    let n = &item["notification"];
    let mut period = String::new();
    if let Some(until) = n["validUntil"].as_str() {
        period = format!(" until {until}");
    }
    format!(
        "{CYAN}{}{RESET}  {BOLD}{}{RESET} {} at {}{}{}  {DIM}from {}{}{RESET}",
        item["recordId"].as_str().unwrap_or("?"),
        n["kind"].as_str().unwrap_or("?"),
        n["subject"]["id"].as_str().unwrap_or("?"),
        n["subject"]["heldBy"].as_str().unwrap_or("?"),
        period,
        match (n["status"].as_str(), item["state"].as_str()) {
            (Some("withdrawn"), _) => " (withdrawn)",
            (_, Some("dismissed")) => " (dismissed)",
            _ => "",
        },
        item["originator"].as_str().unwrap_or("?"),
        match item["relayedBy"].as_array() {
            Some(r) if !r.is_empty() => format!(
                ", relayed by {}",
                r.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" → ")
            ),
            _ => String::new(),
        },
    )
}

/// `list` → `vta/notifications/list/0.1`.
pub async fn cmd_notifications_list(
    client: &VtaClient,
    context: &str,
    opts: &ListOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = json!({ "contextId": context });
    if let Some(k) = &opts.kind {
        req["kind"] = json!(k);
    }
    if let Some(h) = &opts.held_by {
        req["heldBy"] = json!(h);
    }
    if opts.include_dismissed {
        req["includeDismissed"] = json!(true);
    }
    if opts.include_lapsed {
        req["includeLapsed"] = json!(true);
    }
    if let Some(l) = opts.limit {
        req["limit"] = json!(l);
    }
    if let Some(c) = &opts.cursor {
        req["cursor"] = json!(c);
    }
    let resp = client.notifications_list_json(req).await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    let items = resp["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("No notifications held in context '{context}'.");
    } else {
        println!();
        println!("{BOLD}Notifications in context '{context}'{RESET}");
        println!();
        for item in &items {
            println!("  {}", line(item));
        }
        println!();
    }
    if let Some(c) = resp["nextCursor"].as_str() {
        println!("{DIM}More remain: pass --cursor {c}{RESET}");
    }
    Ok(())
}

/// `show` → `vta/notifications/show/0.1`: the record and the delivering document, unchanged.
pub async fn cmd_notifications_show(
    client: &VtaClient,
    context: &str,
    record_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .notifications_show_json(json!({ "contextId": context, "recordId": record_id }))
        .await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    println!();
    println!("  {}", line(&resp["item"]));
    let n = &resp["item"]["notification"];
    println!(
        "  {DIM}audience {}  open with {}{RESET}",
        n["audience"].as_str().unwrap_or("?"),
        n["subject"]["openWith"].as_str().unwrap_or("?")
    );
    println!();
    println!("{BOLD}Delivering document, as received{RESET}");
    println!("{}", serde_json::to_string_pretty(&resp["document"])?);
    Ok(())
}

/// `dismiss` → `vta/notifications/dismiss/0.1`.
pub async fn cmd_notifications_dismiss(
    client: &VtaClient,
    context: &str,
    record_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .notifications_dismiss_json(json!({ "contextId": context, "recordId": record_id }))
        .await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    if resp["changed"].as_bool() == Some(true) {
        println!("{GREEN}\u{2713}{RESET} Dismissed {BOLD}{record_id}{RESET}.");
    } else {
        println!("{BOLD}{record_id}{RESET} was already dismissed.");
    }
    Ok(())
}

/// `deposit` → `vta/notifications/deposit/0.1`: `file` (`-` for stdin) holds the document
/// exactly as received; it is sent as parsed, never through a typed form (VTI-NTF-054).
pub async fn cmd_notifications_deposit(
    client: &VtaClient,
    context: &str,
    file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = if file == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    } else {
        std::fs::read_to_string(file)?
    };
    let document: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{file} does not hold a JSON document: {e}"))?;
    let resp = client
        .notifications_deposit_json(json!({ "contextId": context, "document": document }))
        .await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    println!(
        "{GREEN}\u{2713}{RESET} Deposited {BOLD}{}{RESET} revision {}. Whether the VTA holds it \
         is its acceptance policy's decision: `pnm notifications list --context {context}` shows \
         what it holds.",
        resp["notificationId"].as_str().unwrap_or("?"),
        resp["revision"]
    );
    Ok(())
}
