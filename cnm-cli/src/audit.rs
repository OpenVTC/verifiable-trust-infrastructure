//! `cnm audit verify` — check the VTC's audit hash chain.
//!
//! The community's audit log is a community-admin concern (unlike the
//! VTA's own audit tail, which lives on `pnm`), so the verification
//! surface belongs here.
//!
//! Like `cnm backup`, this is a REST-only super-admin route, so we make
//! a direct authenticated GET (forcing REST regardless of the session's
//! preferred transport) and attach the `Trust-Task` header the route
//! requires.

use serde_json::Value;
use vta_cli_common::render::{DIM, GREEN, RED, RESET};
use vta_sdk::client::VtaClient;

use crate::auth;

/// Canonical HTTP header carrying the Trust-Task URL (mirrors
/// `vti_common::trust_task::HEADER_NAME`).
const TRUST_TASK_HEADER: &str = "Trust-Task";
const VERIFY_TASK: &str = "https://trusttasks.org/spec/audit/verify/0.1";

/// `cnm audit verify` — walk the community's audit chain and report.
///
/// Exits non-zero when the chain does not verify, so this is usable as
/// a scheduled check (`cnm audit verify || alert`).
pub async fn cmd_verify(
    client: &VtaClient,
    keyring_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = client
        .rest_url()
        .ok_or("VTC audit verify requires a REST connection to the VTC")?;
    let token = auth::ensure_authenticated(base, keyring_key).await?;

    let resp = reqwest::Client::new()
        .get(format!("{base}/audit/verify"))
        .bearer_auth(&token)
        .header(TRUST_TASK_HEADER, VERIFY_TASK)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("VTC audit verify failed ({status}): {text}").into());
    }
    let body: Value = serde_json::from_str(&text)
        .map_err(|e| format!("could not parse VTC response: {e} (body: {text})"))?;

    let verified = body["verified"].as_bool().unwrap_or(false);
    let examined = body["entriesExamined"].as_u64().unwrap_or(0);
    let chain_verified = body["entriesVerified"].as_u64().unwrap_or(0);
    let legacy = body["legacySkipped"].as_u64().unwrap_or(0);
    let unparseable = body["unparseableSkipped"].as_u64().unwrap_or(0);

    if verified {
        println!("{GREEN}✓ audit chain verified{RESET}");
    } else {
        println!("{RED}✗ audit chain BROKEN{RESET}");
    }
    println!("  {DIM}entries examined:{RESET} {examined}");
    println!("  {DIM}chain-verified:  {RESET} {chain_verified}");
    if let Some(head) = body["head"].as_str() {
        println!("  {DIM}chain head:      {RESET} {head}");
    }

    // Skipped rows are not a pass — they are rows nothing checked.
    // Surface them at the same prominence as a break so a clean-looking
    // "verified" over a log full of skips can't be misread.
    if legacy > 0 {
        println!(
            "  {RED}legacy rows skipped: {legacy}{RESET} \
             {DIM}(pre-v2 rows are not chain-checked — on a store that should\n\
             \x20  have none, this is itself a finding){RESET}"
        );
    }
    if unparseable > 0 {
        println!(
            "  {RED}unparseable rows skipped: {unparseable}{RESET} \
             {DIM}(corrupt or forward-version rows, also unchecked){RESET}"
        );
    }

    // Signed checkpoints (#708) — the half that resists a store-level
    // adversary. Printed after the chain result and *before* the exit
    // decision, because a green chain over a truncated log is precisely the
    // case an operator must not skim past.
    let checkpoints = &body["checkpoints"];
    let cp_status = checkpoints["status"].as_str().unwrap_or("unknown");
    let cp_detail = checkpoints["detail"].as_str();
    let cp_broken = matches!(cp_status, "truncated" | "headMismatch" | "chainBroken");
    println!();
    match cp_status {
        "consistent" => {
            let attested = checkpoints["attestedEntries"].as_u64().unwrap_or(0);
            let unattested = checkpoints["unattestedEntries"].as_u64().unwrap_or(0);
            let count = checkpoints["verifiedCheckpoints"].as_u64().unwrap_or(0);
            println!(
                "{GREEN}✓ signed checkpoints consistent{RESET} {DIM}({count} verified){RESET}"
            );
            println!("  {DIM}attested entries:{RESET} {attested}");
            if let Some(at) = checkpoints["newestCheckpointAt"].as_str() {
                println!("  {DIM}newest checkpoint:{RESET} {at}");
            }
            if unattested > 0 {
                // Not a failure, but not nothing: this tail is covered by the
                // forgeable chain only, so it is the live truncation window.
                println!(
                    "  {DIM}unattested tail:  {RESET} {unattested}                      {DIM}(written since the last checkpoint — signed by nothing yet){RESET}"
                );
            }
        }
        "noCheckpoints" => {
            println!("{RED}! no signed checkpoints{RESET}");
            if let Some(d) = cp_detail {
                println!("  {DIM}{d}{RESET}");
            }
        }
        _ => {
            println!("{RED}✗ signed checkpoints FAILED ({cp_status}){RESET}");
            if let Some(d) = cp_detail {
                println!("  {RED}{d}{RESET}");
            }
        }
    }

    if let Some(brk) = body.get("chainBreak").filter(|v| !v.is_null()) {
        let kind = brk["kind"].as_str().unwrap_or("?");
        let index = brk["index"].as_u64().unwrap_or(0);
        let event_id = brk["eventId"].as_str().unwrap_or("?");
        println!();
        println!("  {RED}break:{RESET} {kind} at index {index} (event {event_id})");
        match kind {
            "tamperedEntry" => {
                println!("  {DIM}That envelope's content changed after it was written.{RESET}")
            }
            "brokenLink" => println!(
                "  {DIM}An entry was reordered, dropped, or inserted at this point.{RESET}"
            ),
            _ => {}
        }
    }

    if !verified {
        println!();
        println!(
            "{DIM}Note: the chain alone proves internal consistency, not authenticity —\n\
             it is unsigned, so an adversary with store write access can restamp a\n\
             forged suffix. The checkpoint result above is the signed half.{RESET}"
        );
        return Err("audit chain verification failed".into());
    }

    // A broken checkpoint result must fail the command even when the chain
    // verifies — that combination *is* the store-level attack: an internally
    // consistent log that the community key says is missing entries. Exiting
    // 0 here would make `cnm audit verify || alert` silent for the one attack
    // checkpoints exist to catch.
    if cp_broken {
        println!();
        println!(
            "{RED}The hash chain is internally consistent but contradicts a signature made\n\
             with the community key. That is what a store-level tamper looks like:\n\
             the surviving log was re-stamped to look correct.{RESET}"
        );
        return Err("audit checkpoint verification failed".into());
    }
    Ok(())
}
