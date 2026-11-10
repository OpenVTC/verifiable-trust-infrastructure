//! `pnm memory …` (and any CLI that adopts it) — CRUD over the VTA's
//! per-context agent memory (`spec/vta/memory/{put,delete,list}/0.2` and
//! `get/0.1`, #2115; the 0.1 versions are superseded).
//!
//! A per-context key/value store the hosted agent reads before it answers:
//! `plant` upserts an entry, `recall` lists (optionally one key), `forget`
//! deletes one, and `wipe` clears the whole context. Each maps onto one of
//! the SDK memory methods.
//!
//! Two server-side gates gate every operation, and both matter to what an
//! operator sees here:
//!
//! - **Capability** — `MemoryRead` for `list` and `get`, `MemoryWrite` for `put` and
//!   `delete` (`vta-service/src/trust_tasks/memory.rs`). `wipe` therefore
//!   needs both: it lists before it deletes. A `reader` holds only
//!   `MemoryRead`, so `plant` / `forget` / `wipe` are refused for that role.
//! - **Context access** — the isolation boundary. A caller can only touch
//!   memory in a context it is permitted to act in, so a context-A agent
//!   never reaches context-B memory.
//!
//! The context is never defaulted at this layer. A super-admin's access check
//! passes for *any* context id and the memory tasks do not require the context
//! to exist, so a guessed or mistyped id would read and write a context that
//! is not there — silently, and looking exactly like an empty one. The caller
//! names the context or there is no call.

use serde_json::json;
use vta_sdk::prelude::*;
use vta_sdk::protocols::memory::{MemoryItem, MemoryListResponse};
use vta_sdk::specs::vta::memory::{get::v0_2 as get_spec, list::v0_3 as list_spec};

/// The page size `recall` and `wipe` ask for while reading a whole context.
const PAGE: u64 = 500;

/// One live item as `recall` and `wipe` use it: the 0.1 `{key, value}` the
/// `--json` contract has always printed, plus the version `wipe` conditions
/// its delete on.
#[derive(Debug)]
struct Item {
    key: String,
    value: String,
    version: u64,
}

use crate::render::{BOLD, CYAN, DIM, GREEN, RED, RESET, is_json_output, print_json};

/// `plant` → `vta/memory/put/0.2`, unconditional. Upserts `value` under
/// `(context, key)`; re-planting the same key overwrites the stored value.
pub async fn cmd_memory_plant(
    client: &VtaClient,
    context: &str,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .memory_put_versioned(context, key, value, None)
        .await?;
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    let version = resp.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    println!(
        "{GREEN}\u{2713}{RESET} Planted {BOLD}{key}{RESET} in context '{context}' (version {version})."
    );
    println!("  {DIM}{value}{RESET}");
    Ok(())
}

/// `recall` → `vta/memory/get/0.2` for one key, or every page of
/// `vta/memory/list/0.3` for the whole context, for `purpose` — what the
/// caller will use what it reads for (VTI-ACL-103). `None` names none, which
/// the VTA serves under an entry stating `any` and records as unstated.
pub async fn cmd_memory_recall(
    client: &VtaClient,
    context: &str,
    key: Option<&str>,
    purpose: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let items = match key {
        Some(k) => get_item(client, context, k, purpose)
            .await?
            .into_iter()
            .collect(),
        None => list_items(client, context, purpose).await?,
    };

    if is_json_output() {
        // The 0.1 list shape stays the `--json` contract, so scripts written
        // against it keep working: `{ "items": [ { "key", "value" } ] }`.
        let items = items
            .into_iter()
            .map(|i| MemoryItem {
                key: i.key,
                value: i.value,
            })
            .collect();
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

/// `delete` (hidden alias `forget`) → `vta/memory/delete/0.2` for one key.
///
/// 0.2 answers a key holding nothing with `existed: false` rather than an
/// error; `pnm` keeps failing on it, as it did on 0.1's `notFound`, so a
/// mistyped key is never reported as forgotten.
pub async fn cmd_memory_forget(
    client: &VtaClient,
    context: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.memory_delete_versioned(context, key, None).await?;
    if resp.get("existed").and_then(|v| v.as_bool()) != Some(true) {
        return Err(
            format!("no memory under '{key}' in context '{context}' — nothing to delete").into(),
        );
    }
    if is_json_output() {
        print_json(&resp)?;
        return Ok(());
    }
    println!("{GREEN}\u{2713}{RESET} Deleted memory {BOLD}{key}{RESET} in context '{context}'.");
    Ok(())
}

/// `wipe` → list, then delete every key. There is no bulk-delete Trust Task,
/// so this is N round-trips and *not* atomic. Needs both memory capabilities —
/// `MemoryRead` for the list, `MemoryWrite` for the deletes.
///
/// Each delete is conditional on the version the list showed, so an item
/// another writer changed after the operator confirmed is not wiped with it:
/// the `versionConflict` stops the wipe and says where.
///
/// The confirmation is where the operator consents to a destructive op;
/// `--yes` is the only thing allowed to stand in for it. `--json` selects an
/// output format, not consent — so with neither a prompt (JSON mode) nor
/// `--yes`, this refuses rather than proceeds. See [`wipe_guard`].
pub async fn cmd_memory_wipe(
    client: &VtaClient,
    context: &str,
    assume_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let items = list_items(client, context, None).await?;

    if items.is_empty() {
        if is_json_output() {
            print_json(&json!({ "wiped": Vec::<String>::new() }))?;
        } else {
            println!("{DIM}Context '{context}' is already empty — nothing to wipe.{RESET}");
        }
        return Ok(());
    }

    match wipe_guard(assume_yes, is_json_output()) {
        WipeGuard::RefuseJson => {
            return Err("`memory wipe` needs `--yes` in --json mode: there is no \
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
        if let Err(e) = client
            .memory_delete_versioned(context, &item.key, Some(item.version))
            .await
        {
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

/// Every live item in a context, every page, typed-decoded. Decoding into the
/// generated response means a malformed page is an error, not a
/// silently-shortened list — which matters most for `wipe`, which derives
/// *what to delete* from it.
async fn list_items(
    client: &VtaClient,
    context: &str,
    purpose: Option<&str>,
) -> Result<Vec<Item>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query = serde_json::Map::new();
        query.insert("limit".into(), json!(PAGE));
        if let Some(c) = &cursor {
            query.insert("cursor".into(), json!(c));
        }
        let (page, next) =
            decode_page(client.memory_list_page_for(context, query, purpose).await?)?;
        items.extend(page);
        match next {
            Some(n) => cursor = Some(n),
            None => break,
        }
    }
    Ok(items)
}

/// One named item, or `None` when the key holds nothing.
async fn get_item(
    client: &VtaClient,
    context: &str,
    key: &str,
    purpose: Option<&str>,
) -> Result<Option<Item>, Box<dyn std::error::Error>> {
    let resp: get_spec::Response =
        serde_json::from_value(client.memory_get_for(context, &[key], purpose).await?)?;
    Ok(resp.items.into_iter().find_map(live_item))
}

/// Typed decode of one `vta/memory/list/0.3` page: its live items and the
/// cursor for the next. Factored out so the "malformed → error" contract is
/// unit-testable without a live VTA.
fn decode_page(resp: serde_json::Value) -> Result<(Vec<Item>, Option<String>), serde_json::Error> {
    let page: list_spec::Response = serde_json::from_value(resp)?;
    Ok((
        page.items.into_iter().filter_map(live_item).collect(),
        page.next_cursor,
    ))
}

/// A live item from a generated record; a tombstone (no value) is none.
fn live_item<R: serde::Serialize>(record: R) -> Option<Item> {
    // Read through JSON rather than the generated newtypes: the two response
    // modules each generate their own `MemoryRecord`, with the same shape.
    let v = serde_json::to_value(record).ok()?;
    if v.get("deleted").and_then(|d| d.as_bool()) == Some(true) {
        return None;
    }
    Some(Item {
        key: v.get("key")?.as_str()?.to_string(),
        value: v.get("value")?.as_str()?.to_string(),
        version: v.get("version")?.as_u64()?,
    })
}

/// What `wipe` should do about the confirmation, given the two inputs that
/// decide it. Pulled out as a pure function because getting it wrong is
/// destructive (see the `--json` finding): `--yes` always proceeds; without
/// it, JSON mode has no one to prompt so it refuses, and otherwise we confirm.
#[derive(Debug, PartialEq, Eq)]
enum WipeGuard {
    Proceed,
    Confirm,
    RefuseJson,
}

fn wipe_guard(assume_yes: bool, json: bool) -> WipeGuard {
    match (assume_yes, json) {
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
    fn wipe_yes_always_proceeds() {
        // --yes is the operator saying "yes"; it overrides both other inputs.
        assert_eq!(wipe_guard(true, false), WipeGuard::Proceed);
        assert_eq!(wipe_guard(true, true), WipeGuard::Proceed);
    }

    #[test]
    fn wipe_json_without_yes_refuses() {
        // The core finding: an output-format flag is not consent, and there is
        // no prompt to answer — so refuse rather than delete unguarded.
        assert_eq!(wipe_guard(false, true), WipeGuard::RefuseJson);
    }

    #[test]
    fn wipe_interactive_without_yes_confirms() {
        assert_eq!(wipe_guard(false, false), WipeGuard::Confirm);
    }

    fn record(key: &str, value: &str, version: u64) -> serde_json::Value {
        json!({
            "contextId": "c", "key": key, "value": value, "version": version,
            "deleted": false, "updatedAt": "2026-11-09T00:00:00Z"
        })
    }

    #[test]
    fn decode_reads_a_page_its_cursor_and_skips_tombstones() {
        let v = json!({
            "items": [
                record("a", "1", 3),
                { "contextId": "c", "key": "gone", "version": 4, "deleted": true,
                  "updatedAt": "2026-11-09T00:00:00Z" },
                record("b", "2", 5),
            ],
            "nextCursor": "next",
            "highWatermark": 5
        });
        let (items, next) = decode_page(v).expect("well-formed page decodes");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].key, "a");
        assert_eq!(items[1].value, "2");
        assert_eq!(items[1].version, 5, "wipe conditions on this");
        assert_eq!(next.as_deref(), Some("next"));
    }

    #[test]
    fn decode_of_a_malformed_body_errors_rather_than_shortening() {
        // A non-string value must fail the whole decode — never be dropped,
        // which would make `wipe` under-count what it leaves behind.
        let v = json!({ "items": [ { "contextId": "c", "key": "a", "value": 7, "version": 1,
                                     "deleted": false, "updatedAt": "2026-11-09T00:00:00Z" } ],
                        "highWatermark": 1 });
        assert!(decode_page(v).is_err());
    }

    #[test]
    fn count_memories_agrees_the_noun() {
        assert_eq!(count_memories(0), "0 memories");
        assert_eq!(count_memories(1), "1 memory");
        assert_eq!(count_memories(2), "2 memories");
    }
}
