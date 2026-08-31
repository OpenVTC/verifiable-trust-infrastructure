//! `pnm memory …` (and any CLI that adopts it) — CRUD over the VTA's
//! per-context agent memory (`spec/vta/memory/{put,list,delete}/0.1`).
//!
//! A per-context key/value store the hosted agent reads before it answers:
//! `plant` upserts an entry, `recall` lists (optionally one key), `forget`
//! deletes one, and `wipe` clears the whole context. Each maps onto one of
//! the SDK memory methods; every operation is gated server-side on access to
//! the target context, so a caller can only touch memory in a context it is
//! permitted to act in.

use serde_json::json;
use vta_sdk::prelude::*;
use vta_sdk::protocols::memory::{MemoryItem, MemoryListResponse};

use crate::render::{BOLD, CYAN, DIM, GREEN, RED, RESET, is_json_output, print_json};

/// `plant` → `memory_put`. Upserts `value` under `(context, key)`; re-planting
/// the same key overwrites the stored value.
pub async fn cmd_memory_plant(
    client: &VtaClient,
    context: &str,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.memory_put(context, key, value).await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    println!("{GREEN}\u{2713}{RESET} Planted {BOLD}{key}{RESET} in context '{context}'.");
    println!("  {DIM}{value}{RESET}");
    Ok(())
}

/// `recall` → `memory_list`, optionally filtered to a single key.
pub async fn cmd_memory_recall(
    client: &VtaClient,
    context: &str,
    key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut items = list_items(client, context).await?;
    if let Some(k) = key {
        items.retain(|item| item.key == k);
    }

    if is_json_output() {
        // The SDK's own response shape *is* the stable `--json` contract here,
        // so re-emit it rather than hand-building an equivalent that could
        // drift from it.
        print_json(&MemoryListResponse { items })?;
        return Ok(());
    }

    if items.is_empty() {
        match key {
            Some(k) => println!("No memory under '{k}' in context '{context}'."),
            None => println!("Context '{context}' has no memories."),
        }
        return Ok(());
    }

    println!();
    println!("{BOLD}Memory for context '{context}'{RESET}");
    println!();
    for item in &items {
        println!("  {CYAN}{}{RESET}  {}", item.key, item.value);
    }
    println!();
    Ok(())
}

/// `forget` → `memory_delete` for one key.
pub async fn cmd_memory_forget(
    client: &VtaClient,
    context: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.memory_delete(context, key).await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    println!("{GREEN}\u{2713}{RESET} Forgot {BOLD}{key}{RESET} in context '{context}'.");
    Ok(())
}

/// `wipe` → list, then `memory_delete` every key. There is no bulk-delete
/// Trust Task, so this is N round-trips and *not* atomic.
///
/// The confirmation is where the operator consents to a destructive op;
/// `--force` is the only thing allowed to stand in for it. `--json` selects an
/// output format, not consent — so with neither a prompt (JSON mode) nor
/// `--force`, this refuses rather than proceeds. See [`wipe_guard`].
pub async fn cmd_memory_wipe(
    client: &VtaClient,
    context: &str,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let items = list_items(client, context).await?;

    if items.is_empty() {
        if is_json_output() {
            print_json(&json!({ "wiped": Vec::<String>::new() }))?;
        } else {
            println!("{DIM}Context '{context}' is already empty — nothing to wipe.{RESET}");
        }
        return Ok(());
    }

    match wipe_guard(force, is_json_output()) {
        WipeGuard::RefuseJson => {
            return Err("`memory wipe` needs `--force` in --json mode: there is no \
                        prompt to confirm to"
                .into());
        }
        WipeGuard::Confirm => {
            println!(
                "{RED}This wipes all {} in context '{context}'.{RESET}",
                count_memories(items.len())
            );
            let go = dialoguer::Confirm::new()
                .with_prompt("Wipe every memory in this context?")
                .default(false)
                .interact()?;
            if !go {
                println!("Cancelled — nothing was wiped.");
                return Ok(());
            }
        }
        WipeGuard::Proceed => {}
    }

    // Not atomic: on a mid-loop failure, name what did delete before surfacing
    // the error. Re-running `wipe` is safe and finishes the job — but only if
    // the operator can see where it stopped.
    let mut wiped: Vec<String> = Vec::with_capacity(items.len());
    for item in &items {
        if let Err(e) = client.memory_delete(context, &item.key).await {
            return Err(format!(
                "wiped {} of {} before failing on '{}': {e}",
                wiped.len(),
                items.len(),
                item.key,
            )
            .into());
        }
        wiped.push(item.key.clone());
    }

    if is_json_output() {
        print_json(&json!({ "wiped": wiped }))?;
        return Ok(());
    }
    println!(
        "{RED}\u{2713}{RESET} Wiped {} from context '{context}'.",
        count_memories(wiped.len())
    );
    Ok(())
}

/// Fetch and typed-decode a context's memory. Decoding into the SDK body means
/// a malformed response is an error, not a silently-shortened list — which
/// matters most for `wipe`, which derives *what to delete* from it.
async fn list_items(
    client: &VtaClient,
    context: &str,
) -> Result<Vec<MemoryItem>, Box<dyn std::error::Error>> {
    let resp = client.memory_list(context).await?;
    Ok(decode_items(resp)?)
}

/// Typed decode of a `vta/memory/list` response body into its entries.
/// Factored out so the "malformed → error" contract is unit-testable without a
/// live VTA.
fn decode_items(resp: serde_json::Value) -> Result<Vec<MemoryItem>, serde_json::Error> {
    let parsed: MemoryListResponse = serde_json::from_value(resp)?;
    Ok(parsed.items)
}

/// What `wipe` should do about the confirmation, given the two inputs that
/// decide it. Pulled out as a pure function because getting it wrong is
/// destructive (see the `--json` finding): `--force` always proceeds; without
/// it, JSON mode has no one to prompt so it refuses, and otherwise we confirm.
#[derive(Debug, PartialEq, Eq)]
enum WipeGuard {
    Proceed,
    Confirm,
    RefuseJson,
}

fn wipe_guard(force: bool, json: bool) -> WipeGuard {
    match (force, json) {
        (true, _) => WipeGuard::Proceed,
        (false, true) => WipeGuard::RefuseJson,
        (false, false) => WipeGuard::Confirm,
    }
}

/// "1 memory" / "N memories" — count with the noun agreed.
fn count_memories(n: usize) -> String {
    if n == 1 {
        "1 memory".to_string()
    } else {
        format!("{n} memories")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_force_always_proceeds() {
        // --force is the operator saying "yes"; it overrides both other inputs.
        assert_eq!(wipe_guard(true, false), WipeGuard::Proceed);
        assert_eq!(wipe_guard(true, true), WipeGuard::Proceed);
    }

    #[test]
    fn wipe_json_without_force_refuses() {
        // The core finding: an output-format flag is not consent, and there is
        // no prompt to answer — so refuse rather than delete unguarded.
        assert_eq!(wipe_guard(false, true), WipeGuard::RefuseJson);
    }

    #[test]
    fn wipe_interactive_without_force_confirms() {
        assert_eq!(wipe_guard(false, false), WipeGuard::Confirm);
    }

    #[test]
    fn decode_reads_camelcase_items() {
        let v = json!({ "items": [
            { "key": "a", "value": "1" },
            { "key": "b", "value": "2" },
        ] });
        let items = decode_items(v).expect("well-formed body decodes");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].key, "a");
        assert_eq!(items[1].value, "2");
    }

    #[test]
    fn decode_of_a_malformed_body_errors_rather_than_shortening() {
        // A non-string value must fail the whole decode — never be dropped,
        // which would make `wipe` under-count what it leaves behind.
        let v = json!({ "items": [ { "key": "a", "value": 7 } ] });
        assert!(decode_items(v).is_err());
    }

    #[test]
    fn count_memories_agrees_the_noun() {
        assert_eq!(count_memories(0), "0 memories");
        assert_eq!(count_memories(1), "1 memory");
        assert_eq!(count_memories(2), "2 memories");
    }
}
