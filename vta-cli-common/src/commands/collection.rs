//! `pnm collection …` — which party collects a persona DID's messages at its mediator
//! (`vta/collection/{claim,release,list}/0.1`, `vta/collection/settings/{show,set}/0.1`,
//! VTI-NTF-080 – 098).
//!
//! The mediator permits one connection per DID, so the VTA and a client agree which of them
//! holds it: the VTA collects for every persona no client has claimed (unless collection by
//! default is disabled for the persona's context, or the operator has suspended it), and a
//! client that holds the connection itself claims the persona first, under a lease. These
//! commands make, renew, release and list those claims, and show and change each context's
//! setting.

use serde_json::{Value, json};
use vta_sdk::prelude::*;

use crate::render::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW, is_json_output, print_json};

/// Options for `collection list`.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub identifier: Option<String>,
    pub collector: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

/// Whether `e` is the declared refusal `local` (`claimHeld`, `notCollectable`, …) of any
/// `vta/collection/*` task.
fn refused_as(e: &VtaError, local: &str) -> bool {
    e.rejection_code()
        .is_some_and(|c| c == local || c.ends_with(&format!(":{local}")))
}

/// The refusal, with the command the operator most likely wants next.
fn explain(
    e: VtaError,
    context: &str,
    identifier: &str,
    claiming: bool,
) -> Box<dyn std::error::Error> {
    let hint = if refused_as(&e, "claimHeld") {
        format!(
            "Another client holds a collection claim for {identifier}. Release it — it then \
             ends at its stated end, because that client may still be connected — and claim \
             again once it has ended:\n  pnm collection release --context {context} \
             --identifier {identifier}\n  pnm collection list --context {context} --identifier \
             {identifier}"
        )
    } else if refused_as(&e, "claimNotRenewable") {
        format!(
            "Your claim for {identifier} was released by another party and cannot be renewed. \
             Stop collecting before its end (`pnm collection list --context {context} \
             --identifier {identifier}` shows it), and claim again once it has ended."
        )
    } else if refused_as(&e, "notCollectable") {
        format!(
            "{identifier} is not an identifier this VTA collects for in context '{context}': it \
             holds no messaging keys for it there, its DID document advertises no mediated \
             transport, or it is the VTA's own identity, another node's or one provisioned for \
             another party, which its holder collects for. `pnm collection list --context \
             {context}` shows the identifiers it does.{}",
            if claiming {
                ""
            } else {
                " There is no claim to release."
            }
        )
    } else {
        return Box::new(e);
    };
    format!("{e}\n\n{hint}").into()
}

/// `claim` → `vta/collection/claim/0.1`.
pub async fn cmd_collection_claim(
    client: &VtaClient,
    context: &str,
    identifier: &str,
    duration_seconds: Option<i64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = json!({ "contextId": context, "identifier": identifier });
    if let Some(d) = duration_seconds {
        req["durationSeconds"] = json!(d);
    }
    let resp = client
        .collection_claim_json(req)
        .await
        .map_err(|e| explain(e, context, identifier, true))?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    let verb = if resp["renewed"].as_bool() == Some(true) {
        "Renewed"
    } else {
        "Claimed"
    };
    println!(
        "{GREEN}\u{2713}{RESET} {verb} {BOLD}{identifier}{RESET} until {}. The VTA has stopped \
         collecting for it; stop collecting before that end unless you renew.",
        resp["endsAt"].as_str().unwrap_or("?")
    );
    Ok(())
}

/// `release` → `vta/collection/release/0.1`.
pub async fn cmd_collection_release(
    client: &VtaClient,
    context: &str,
    identifier: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .collection_release_json(json!({ "contextId": context, "identifier": identifier }))
        .await
        .map_err(|e| explain(e, context, identifier, false))?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    match resp["endsAt"].as_str() {
        Some(at) => println!(
            "{GREEN}\u{2713}{RESET} Released the claim for {BOLD}{identifier}{RESET}; it ends \
             at {at}."
        ),
        None => println!("No claim for {BOLD}{identifier}{RESET} was in force; nothing changed."),
    }
    Ok(())
}

fn line(item: &Value) -> String {
    let id = item["identifier"].as_str().unwrap_or("?");
    match item["collector"].as_str() {
        Some("client") => {
            let c = &item["claim"];
            format!(
                "{CYAN}{id}{RESET}  {BOLD}client{RESET} {}  {DIM}until {}{}{RESET}",
                c["claimant"].as_str().unwrap_or("?"),
                c["endsAt"].as_str().unwrap_or("?"),
                if c["renewable"].as_bool() == Some(false) {
                    ", not renewable"
                } else {
                    ""
                }
            )
        }
        Some("none") => format!(
            "{CYAN}{id}{RESET}  {YELLOW}nobody{RESET}  {DIM}({}){RESET}",
            match item["notCollectedReason"].as_str() {
                Some("disabled") =>
                    "collection by default is disabled for this context, or suspended by the operator",
                Some("limit") => "the VTA is at its bound on collected identifiers",
                Some("conflict") =>
                    "another connection kept evicting the VTA's; claim it from that client",
                Some(other) => other,
                None => "?",
            }
        ),
        Some(c) => format!("{CYAN}{id}{RESET}  {BOLD}{c}{RESET}"),
        None => format!("{CYAN}{id}{RESET}  ?"),
    }
}

/// `list` → `vta/collection/list/0.1`.
pub async fn cmd_collection_list(
    client: &VtaClient,
    context: &str,
    opts: &ListOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = json!({ "contextId": context });
    if let Some(i) = &opts.identifier {
        req["identifier"] = json!(i);
    }
    if let Some(c) = &opts.collector {
        req["collector"] = json!(c);
    }
    if let Some(l) = opts.limit {
        req["limit"] = json!(l);
    }
    if let Some(c) = &opts.cursor {
        req["cursor"] = json!(c);
    }
    let resp = client.collection_list_json(req).await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    let items = resp["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("No identifiers in context '{context}' that this VTA would collect for.");
    } else {
        println!();
        println!("{BOLD}Collection in context '{context}'{RESET}");
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

/// `status` → `vta/collection/settings/show/0.1`, then `vta/collection/list/0.1` (every page)
/// for the counts by collector and reason.
pub async fn cmd_collection_status(
    client: &VtaClient,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let shown = client
        .collection_settings_show_json(json!({ "contextId": context }))
        .await?;
    let mut items: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut req = json!({ "contextId": context, "limit": 200 });
        if let Some(c) = &cursor {
            req["cursor"] = json!(c);
        }
        let page = client.collection_list_json(req).await?;
        items.extend(page["items"].as_array().cloned().unwrap_or_default());
        match page["nextCursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for item in &items {
        let key = match item["collector"].as_str() {
            Some("none") => format!(
                "none ({})",
                item["notCollectedReason"].as_str().unwrap_or("?")
            ),
            Some(c) => c.to_string(),
            None => "?".into(),
        };
        *counts.entry(key).or_default() += 1;
    }
    if is_json_output() {
        print_json(&json!({
            "setting": shown["setting"],
            "identifiers": items.len(),
            "byCollector": counts,
        }))?;
        return Ok(());
    }
    let setting = &shown["setting"];
    let on = setting["collectByDefault"].as_bool() == Some(true);
    let suspended = setting["suspendedByOperator"].as_bool() == Some(true);
    println!();
    println!("{BOLD}Collection in context '{context}'{RESET}");
    println!();
    println!(
        "  Collection by default: {}",
        if on {
            format!("{GREEN}enabled{RESET}")
        } else {
            format!("{YELLOW}disabled{RESET}")
        }
    );
    match (setting["changedBy"].as_str(), setting["changedAt"].as_str()) {
        (Some(by), Some(at)) => println!("  Last changed:          {at} by {by}"),
        _ => println!("  Last changed:          {DIM}never (enabled by default){RESET}"),
    }
    if suspended {
        println!(
            "  {YELLOW}Suspended by the operator:{RESET} the VTA collects for no unclaimed \
             persona in any context until the operator lifts it; this context's setting \
             applies again then."
        );
    }
    println!();
    if items.is_empty() {
        println!("  No identifiers in this context that this VTA would collect for.");
    } else {
        println!("  {} identifier(s):", items.len());
        for (k, n) in &counts {
            println!("    {k:<20} {n}");
        }
    }
    println!();
    println!("{DIM}`pnm collection list --context {context}` shows each one.{RESET}");
    Ok(())
}

/// `enable` / `disable` → `vta/collection/settings/set/0.1`.
pub async fn cmd_collection_set(
    client: &VtaClient,
    context: &str,
    collect_by_default: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .collection_settings_set_json(
            json!({ "contextId": context, "collectByDefault": collect_by_default }),
        )
        .await
        .map_err(|e| -> Box<dyn std::error::Error> {
            if matches!(e, VtaError::Forbidden(_))
                || e.rejection_code()
                    .is_some_and(|c| c.ends_with("permissionDenied"))
            {
                format!(
                    "{e}\n\nChanging collection by default for '{context}' needs administrative \
                     authority over it: an admin entry whose contexts include '{context}' or an \
                     ancestor of it, or a super-admin. Anyone with standing there can read it:\n  \
                     pnm collection status --context {context}"
                )
                .into()
            } else {
                Box::new(e)
            }
        })?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    let word = if collect_by_default {
        "enabled"
    } else {
        "disabled"
    };
    if resp["changed"].as_bool() == Some(true) {
        println!(
            "{GREEN}\u{2713}{RESET} Collection by default {word} for context '{context}'.{}",
            if collect_by_default {
                " The VTA is starting to collect for its unclaimed personas."
            } else {
                " The VTA has stopped collecting for its unclaimed personas and closed those \
                 connections."
            }
        );
    } else {
        println!(
            "Collection by default was already {word} for context '{context}'; nothing changed."
        );
    }
    if resp["setting"]["suspendedByOperator"].as_bool() == Some(true) {
        println!(
            "{YELLOW}Note:{RESET} the operator has suspended collection on this VTA; nothing is \
             collected until it is lifted."
        );
    }
    Ok(())
}
