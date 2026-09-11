use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Cell, Row, Table};
use vta_sdk::prelude::*;
use vta_sdk::protocols::audit_management::list::{AuditEnvelope, ListAuditLogsResultBody};

use crate::display::{NameBook, book_from_acl, named_did_cell};
use crate::render::{is_full_display, print_full_entry_owned, print_full_list_title, print_widget};

/// Display audit logs with beautiful colored formatting.
pub async fn cmd_list_audit_logs(
    client: &VtaClient,
    params: &ListAuditLogsBody,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.list_audit_logs(params).await?;

    if result.entries.is_empty() {
        println!("  No audit log entries found.");
        return Ok(());
    }

    // Audit rows carry only an actor DID — "who did this" is exactly the
    // question a log is read to answer, so it is worth one extra request to
    // put names on them. Best-effort: an operator may hold audit-read without
    // ACL-read, and a naming failure must never fail the command.
    let mut book = NameBook::new();
    if let Ok(acl) = client.list_acl(None).await {
        book_from_acl(&mut book, &acl.entries);
    }

    if is_full_display() {
        print_full_list_title("Audit Log", result.entries.len());
        for entry in &result.entries {
            let ts = format_recorded_at(&entry.recorded_at);
            let actor = entry.actor.as_deref().unwrap_or("—");
            let target = entry.target.as_deref().unwrap_or("—");
            let channel = detail_str(entry, "channel").unwrap_or_else(|| "—".to_string());
            let context = entry.context_id.as_deref().unwrap_or("—");
            let mut fields = vec![
                ("ID", entry.event_id.clone()),
                ("Timestamp", ts),
                ("Action", entry.action.clone()),
            ];
            if let Some(name) = book.name_of(actor) {
                fields.push(("Actor", name));
            }
            // Actor DID stays in full — an audit trail is evidence.
            fields.push(("Actor DID", actor.to_string()));
            fields.push(("Resource", target.to_string()));
            fields.push(("Channel", channel));
            fields.push(("Context", context.to_string()));
            fields.push((
                "Outcome",
                entry.outcome.clone().unwrap_or_else(|| "—".to_string()),
            ));
            if let Some(reason) = detail_str(entry, "reason") {
                fields.push(("Reason", reason));
            }
            print_full_entry_owned(&fields);
        }
        print_cursor_footer(&result);
        return Ok(());
    }

    println!("\n  \x1b[1mAudit Log\x1b[0m\n");

    // Build table rows
    let rows: Vec<Row> = result
        .entries
        .iter()
        .map(|entry| {
            // Format timestamp in operator's local timezone.
            let ts = format_recorded_at(&entry.recorded_at);
            let outcome = entry.outcome.as_deref().unwrap_or("—");

            // Color the outcome
            let outcome_style = if outcome == "success" {
                Style::default().fg(Color::Green)
            } else if outcome.starts_with("denied") {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow)
            };

            // Color the action
            let action_style = if entry.action.starts_with("auth.") {
                Style::default().fg(Color::Cyan)
            } else if entry.action.starts_with("key.") || entry.action.starts_with("seed.") {
                Style::default().fg(Color::Magenta)
            } else if entry.action.starts_with("acl.") {
                Style::default().fg(Color::Yellow)
            } else if entry.action.starts_with("session.") {
                Style::default().fg(Color::Blue)
            } else {
                Style::default()
            };

            // Actor: the entry's name when we have one, else the shortened
            // DID. (The previous `&entry.actor[..29]` sliced on a byte
            // boundary and would panic on a multi-byte character.)
            let resource_display = entry.target.as_deref().unwrap_or("\u{2014}");

            Row::new(vec![
                Cell::from(Span::styled(ts, Style::default().fg(Color::DarkGray))),
                Cell::from(Span::styled(entry.action.clone(), action_style)),
                named_did_cell(&book, entry.actor.as_deref().unwrap_or("\u{2014}")),
                Cell::from(resource_display.to_string()),
                Cell::from(Span::styled(outcome.to_string(), outcome_style)),
            ])
        })
        .collect();

    let header = Row::new(vec![
        Cell::from(Span::styled(
            "Timestamp",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Action",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Actor",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Resource",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Outcome",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
    ]);

    let row_count = result.entries.len();

    // `Actor` holds DID strings that can run 50+ chars — use `Min` so
    // the column expands on wide terminals rather than cutting off at
    // a fixed 30 (operators still see the ellipsis-truncated DID on
    // narrow screens, and can use `--full-display` for full values).
    let table = Table::new(
        rows,
        [
            Constraint::Length(25), // Timestamp (local tz with offset)
            Constraint::Length(22), // Action
            Constraint::Min(30),    // Actor
            Constraint::Min(16),    // Resource
            Constraint::Length(20), // Outcome
        ],
    )
    .header(header)
    .column_spacing(2);

    let height = row_count as u16 + 2; // rows + header + spacing
    print_widget(table, height);

    print_cursor_footer(&result);

    Ok(())
}

/// Render `recordedAt` (RFC 3339 on the wire) in the operator's local
/// timezone, falling back to the raw string if it does not parse —
/// an audit row must still be readable when its timestamp is odd.
fn format_recorded_at(recorded_at: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(recorded_at) {
        Ok(dt) => crate::duration::format_local_datetime(dt.with_timezone(&chrono::Utc)),
        Err(_) => recorded_at.to_string(),
    }
}

/// Pull a string member out of the canonical `detail` object.
fn detail_str(entry: &AuditEnvelope, key: &str) -> Option<String> {
    entry
        .detail
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

/// Print the continuation hint. Paging is by opaque cursor, so there
/// is no page count to show — the only thing an operator can act on is
/// whether another page exists and the token that fetches it.
fn print_cursor_footer(result: &ListAuditLogsResultBody) {
    if let Some(cursor) = &result.cursor {
        println!(
            "\n  \x1b[2mMore entries \u{2014} fetch the next page with --cursor {cursor}\x1b[0m"
        );
        println!("  \x1b[2m(keep the same filters; changing them invalidates the cursor)\x1b[0m");
    }
}

/// Display the current audit retention period.
pub async fn cmd_get_retention(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.get_audit_retention().await?;
    println!("\n  \x1b[1mAudit Retention\x1b[0m");
    println!(
        "  Retention period: \x1b[36m{}\x1b[0m days",
        result.retention_days
    );
    println!();
    Ok(())
}

/// Update the audit retention period.
pub async fn cmd_update_retention(
    client: &VtaClient,
    days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.update_audit_retention(days).await?;
    println!(
        "\n  \x1b[32m\u{2713}\x1b[0m Audit retention updated to \x1b[36m{}\x1b[0m days",
        result.retention_days
    );
    println!();
    Ok(())
}
