//! Method-neutral DID reads (`vta/dids/{list,get,methods/list}/0.1`): every
//! identity the VTA holds, whatever its method
//! (`docs/05-design-notes/did-management.md`).
//!
//! `pnm did-mgmt dids list` and `get` answer here for every method — they used
//! to ask the did:webvh family alone, and said "No WebVH DIDs found" to an
//! agent whose identities were all did:webs. `pnm webs list` is the same
//! listing narrowed to did:webs. What an identity *does* stays with its
//! method's own commands.

use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use serde_json::Value;
use vta_sdk::client::{DidListFilter, VtaClient};

use crate::display::{
    NAME_HEADER, book_from_vta, did_cell, full_display_pairs, name_cell, resolve_agent_names_into,
};
use crate::render::{
    is_full_display, is_json_output, print_full_entry_owned, print_full_list_title, print_json,
    print_widget,
};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// One identity as the command reads it: the wire summary, kept as JSON so the
/// listing never drops a member a newer VTA sends.
struct Entry {
    v: Value,
}

impl Entry {
    fn s(&self, k: &str) -> String {
        self.v
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }
    fn b(&self, k: &str) -> bool {
        self.v.get(k).and_then(Value::as_bool).unwrap_or(false)
    }
}

/// Header cells and widths together, so a conditional Name column cannot shift
/// every width one place left (see `webvh::did_list_columns`' history).
fn columns(show_names: bool) -> (Vec<&'static str>, Vec<Constraint>) {
    let mut headers = vec!["DID", "Method", "Context", "Server", "Created"];
    let mut constraints = vec![
        Constraint::Min(46),    // DID
        Constraint::Length(8),  // Method
        Constraint::Length(16), // Context
        Constraint::Length(16), // Server
        Constraint::Length(16), // Created
    ];
    if show_names {
        headers.insert(0, NAME_HEADER);
        constraints.insert(0, Constraint::Min(16));
    }
    (headers, constraints)
}

fn created(v: &str, full: bool) -> String {
    chrono::DateTime::parse_from_rfc3339(v)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format(if full {
                    "%Y-%m-%d %H:%M:%S %:z"
                } else {
                    "%Y-%m-%d %H:%M"
                })
                .to_string()
        })
        .unwrap_or_else(|_| v.to_string())
}

/// `dids list` — every identity the caller may see, read to the end.
pub async fn cmd_dids_list(client: &VtaClient, filter: &DidListFilter) -> CmdResult {
    let dids = client.list_dids(filter).await?;
    if is_json_output() {
        print_json(&serde_json::json!({ "dids": dids }))?;
        return Ok(());
    }
    if dids.is_empty() {
        println!("No DIDs found.");
        return Ok(());
    }
    let rows: Vec<Entry> = dids
        .iter()
        .map(|d| serde_json::to_value(d).map(|v| Entry { v }))
        .collect::<Result<_, _>>()?;

    let mut book = book_from_vta(client).await;
    resolve_agent_names_into(
        &mut book,
        rows.iter().map(|r| r.v["did"].as_str().unwrap_or("")),
    )
    .await;

    if is_full_display() {
        print_full_list_title("DIDs", rows.len());
        for r in &rows {
            let did = r.s("did");
            let mut fields = full_display_pairs(&book, &did);
            fields.push(("Method", r.s("method")));
            fields.push(("Context", r.s("contextId")));
            if !r.s("serverId").is_empty() {
                fields.push(("Server", r.s("serverId")));
            }
            if !r.s("class").is_empty() {
                fields.push(("Class", r.s("class")));
            }
            if r.b("primary") {
                fields.push(("Context DID", "yes".to_string()));
            }
            if r.b("deactivated") {
                fields.push(("Deactivated", "yes".to_string()));
            }
            fields.push(("Created", created(&r.s("createdAt"), true)));
            print_full_entry_owned(&fields);
        }
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let show_names = book.names_any(rows.iter().map(|r| r.v["did"].as_str().unwrap_or("")));
    let (header_cells, constraints) = columns(show_names);
    let header = Row::new(header_cells).style(header_style).bottom_margin(1);
    let table_rows: Vec<Row> = rows
        .iter()
        .map(|r| {
            let did = r.s("did");
            let mut method = r.s("method");
            if r.b("deactivated") {
                method.push_str(" (ended)");
            }
            let mut cells = vec![
                did_cell(&did),
                Cell::from(method),
                Cell::from(r.s("contextId")),
                Cell::from(r.s("serverId")),
                Cell::from(created(&r.s("createdAt"), false))
                    .style(Style::default().fg(Color::DarkGray)),
            ];
            if show_names {
                cells.insert(0, name_cell(&book, &did));
            }
            Row::new(cells)
        })
        .collect();
    let table = Table::new(table_rows, constraints)
        .header(header)
        .column_spacing(2)
        .block(
            Block::bordered()
                .title(format!(" DIDs ({}) ", rows.len()))
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    print_widget(table, rows.len() as u16 + 4);
    crate::render::print_truncation_hint();
    Ok(())
}

/// `dids get <did>` — one identity's summary, whatever its method.
pub async fn cmd_dids_get(client: &VtaClient, did: &str) -> CmdResult {
    let summary = client.get_did(did).await?;
    if is_json_output() {
        print_json(&summary)?;
        return Ok(());
    }
    let r = Entry {
        v: serde_json::to_value(&summary)?,
    };
    println!("DID:");
    println!("  DID:             {}", r.s("did"));
    println!("  Method:          {}", r.s("method"));
    println!("  Context:         {}", r.s("contextId"));
    if !r.s("class").is_empty() {
        println!("  Class:           {}", r.s("class"));
    }
    println!(
        "  Context DID:     {}",
        if r.b("primary") { "yes" } else { "no" }
    );
    if r.b("deactivated") {
        println!("  Deactivated:     yes");
    }
    if !r.s("serverId").is_empty() {
        println!("  Server:          {}", r.s("serverId"));
    }
    if !r.s("signingKeyId").is_empty() {
        println!("  Signing key:     {}", r.s("signingKeyId"));
    }
    if !r.s("keyAgreementKeyId").is_empty() {
        println!("  Key agreement:   {}", r.s("keyAgreementKeyId"));
    }
    for aka in r.v["alsoKnownAs"].as_array().into_iter().flatten() {
        println!("  Also known as:   {}", aka.as_str().unwrap_or(""));
    }
    if let Some(details) = r.v["methodDetails"].as_object() {
        for (method, members) in details {
            for (k, v) in members.as_object().into_iter().flatten() {
                let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                println!("  {method}.{k:<12} {v}");
            }
        }
    }
    println!("  Created:         {}", created(&r.s("createdAt"), true));
    println!("  Updated:         {}", created(&r.s("updatedAt"), true));
    Ok(())
}

/// `dids methods` — which DID methods the VTA holds, lists and creates now.
pub async fn cmd_dids_methods_list(client: &VtaClient) -> CmdResult {
    let methods = client.did_methods().await?;
    if is_json_output() {
        print_json(&serde_json::json!({ "methods": methods }))?;
        return Ok(());
    }
    for m in &methods {
        let v = serde_json::to_value(m)?;
        let s = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        let classes: Vec<&str> = v["classes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        println!(
            "{:<8} listed: {:<3}  creatable: {:<3}{}",
            v["method"].as_str().unwrap_or(""),
            if s("listed") { "yes" } else { "no" },
            if s("creatable") { "yes" } else { "no" },
            if classes.is_empty() {
                String::new()
            } else {
                format!("  classes: {}", classes.join(", "))
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header and the widths must describe the same columns. They are
    /// separate lists in ratatui, and a short widths list silently drops the
    /// trailing columns while shifting every width onto the wrong one — which
    /// is how `dids list` came to render a full-width name beside a truncated
    /// DID, with `Created` missing altogether.
    #[test]
    fn did_list_headers_and_widths_describe_the_same_columns() {
        for show_names in [false, true] {
            let (headers, constraints) = columns(show_names);
            assert_eq!(
                headers.len(),
                constraints.len(),
                "header/width mismatch with show_names={show_names}"
            );
        }
    }

    /// The DID column is the flexing one, and it flexes from a width that can
    /// still hold an abbreviated `did:webvh:…:<host>:<path>`. Pinned because
    /// the failure mode is not a panic or a wrong value — it is a table that
    /// renders, looks fine, and cannot be read.
    #[test]
    fn did_column_gets_the_width_a_webvh_did_needs() {
        let (headers, constraints) = columns(true);
        let did_at = headers
            .iter()
            .position(|h| *h == "DID")
            .expect("DID column present");
        assert_eq!(constraints[did_at], Constraint::Min(46));

        // …and the name column must not be the one absorbing the spare width.
        let name_at = headers
            .iter()
            .position(|h| *h == NAME_HEADER)
            .expect("Name column present");
        assert_eq!(constraints[name_at], Constraint::Min(16));
    }
}
