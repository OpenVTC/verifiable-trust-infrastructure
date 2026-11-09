//! `pnm memory history` — who read or changed a context's agent memory, and
//! when (#2116).
//!
//! A view over the audit trail (`audit/list/0.2`), not a store of its own: one
//! query per memory action, merged newest first. The trail's action filter is
//! an exact match by design, so "every memory action" is four queries rather
//! than a prefix. Reading the trail needs what `pnm audit list` needs.
//!
//! What a row can say is bounded by VTI-AUD-005: a memory key is personal data,
//! so the trail never holds one. Each row names the item it touched, or the
//! items a read returned, by a keyed commitment (`hmac-sha256:<key id>:<hex>`)
//! that only the VTA can recompute — the same commitment for the same item, so
//! two rows about one item can be matched by eye. History therefore shows *who*
//! acted, *when*, *how* (put, delete, list, get) and *how many* items a read
//! returned, but not which key was read.

use vta_sdk::prelude::*;
use vta_sdk::protocols::audit_management::list::{AuditEnvelope, ListAuditLogsBody};

use crate::render::{BOLD, CYAN, DIM, RESET, is_json_output, print_json};

/// The actions the memory tasks record (`vta-service/src/trust_tasks/memory.rs`).
pub const MEMORY_ACTIONS: [&str; 4] = ["memory.put", "memory.delete", "memory.list", "memory.get"];

/// Rows fetched per action per page.
const PAGE: u64 = 200;

/// The filters `history` applies on top of the context.
#[derive(Debug, Default, Clone)]
pub struct HistoryFilter {
    pub actor: Option<String>,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    /// At most this many rows in all, newest first.
    pub limit: usize,
}

pub async fn cmd_memory_history(
    client: &VtaClient,
    context: &str,
    filter: &HistoryFilter,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for action in MEMORY_ACTIONS {
        let mut cursor = None;
        let mut fetched = 0usize;
        loop {
            let page = client
                .list_audit_logs(&ListAuditLogsBody {
                    from: filter.from,
                    to: filter.to,
                    action: Some(action.to_string()),
                    actor: filter.actor.clone(),
                    outcome: None,
                    context_id: Some(context.to_string()),
                    cursor,
                    limit: Some(PAGE),
                })
                .await?;
            fetched += page.entries.len();
            rows.extend(page.entries);
            // Each action's pages come newest first, so once this action alone
            // has given `limit` rows, nothing older from it can make the cut.
            match page.next_cursor {
                Some(next) if fetched < filter.limit => cursor = Some(next),
                _ => break,
            }
        }
    }
    let rows = newest_first(rows, filter.limit);

    if is_json_output() {
        print_json(&rows)?;
        return Ok(());
    }
    if rows.is_empty() {
        println!("No memory activity recorded for context '{context}'.");
        return Ok(());
    }
    println!();
    println!("{BOLD}Memory activity in context '{context}'{RESET} {DIM}(newest first){RESET}");
    println!();
    for r in &rows {
        println!(
            "  {DIM}{}{RESET}  {CYAN}{:<13}{RESET} {}  {}",
            r.recorded_at,
            r.action,
            r.actor.as_deref().unwrap_or("(erased)"),
            summary(r),
        );
    }
    println!();
    println!(
        "{DIM}Items are named by commitment, never by key (VTI-AUD-005); the same item \
         carries the same commitment.{RESET}"
    );
    Ok(())
}

/// Every row, newest first, at most `limit`.
fn newest_first(mut rows: Vec<AuditEnvelope>, limit: usize) -> Vec<AuditEnvelope> {
    // RFC 3339 in UTC from one writer sorts lexically; the event id breaks ties
    // so the order is stable.
    rows.sort_by(|a, b| {
        b.recorded_at
            .cmp(&a.recorded_at)
            .then_with(|| b.event_id.cmp(&a.event_id))
    });
    rows.truncate(limit);
    rows
}

/// What one row says about the items: the item a write touched, or how many a
/// read returned.
fn summary(r: &AuditEnvelope) -> String {
    // The stored row's free-text detail is the envelope's `reason` member.
    let detail = r
        .detail
        .get("reason")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let items = detail
        .split_whitespace()
        .find_map(|w| w.strip_prefix("items="));
    match (r.action.as_str(), items) {
        ("memory.list" | "memory.get", Some(n)) => format!("read {n} item(s)"),
        (_, _) => match r.target.as_deref() {
            Some(t) => format!("item {}", short(t)),
            None => String::new(),
        },
    }
}

/// `hmac-sha256:<key id>:<hex>` shortened to its distinguishing tail.
fn short(reference: &str) -> String {
    match reference.rsplit_once(':') {
        Some((_, hex)) if reference.starts_with("hmac-sha256:") => {
            format!("#{}", &hex[..hex.len().min(12)])
        }
        _ => reference.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(at: &str, action: &str, target: Option<&str>, detail: Option<&str>) -> AuditEnvelope {
        let mut d = serde_json::Map::new();
        if let Some(x) = detail {
            d.insert("reason".into(), json!(x));
        }
        AuditEnvelope {
            event_id: format!("{at}-{action}"),
            recorded_at: at.into(),
            action: action.into(),
            outcome: Some("success".into()),
            actor: Some("did:key:zAgent".into()),
            target: target.map(str::to_string),
            context_id: Some("ctx".into()),
            detail: d,
        }
    }

    #[test]
    fn rows_from_every_action_merge_newest_first_and_stop_at_the_limit() {
        let rows = newest_first(
            vec![
                row("2026-11-09T10:00:00Z", "memory.put", None, None),
                row("2026-11-09T12:00:00Z", "memory.get", None, None),
                row("2026-11-09T11:00:00Z", "memory.list", None, None),
            ],
            2,
        );
        assert_eq!(
            rows.iter().map(|r| r.action.as_str()).collect::<Vec<_>>(),
            ["memory.get", "memory.list"]
        );
    }

    #[test]
    fn a_read_says_how_many_items_and_a_write_which_item_by_commitment() {
        let get = row(
            "t",
            "memory.get",
            None,
            Some("items=2 refs=hmac-sha256:k:aaaa,hmac-sha256:k:bbbb"),
        );
        assert_eq!(summary(&get), "read 2 item(s)");
        let put = row(
            "t",
            "memory.put",
            Some(
                "hmac-sha256:3f0e1c2a-0000-4000-8000-000000000000:0123456789abcdef0123456789abcdef",
            ),
            None,
        );
        assert_eq!(summary(&put), "item #0123456789ab");
    }
}
