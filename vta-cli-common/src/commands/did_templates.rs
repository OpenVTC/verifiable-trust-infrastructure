//! DID template commands — offline (Phase 1) and online (Phase 2 global scope).
//!
//! Offline: validate a file, init a starter from an embedded builtin, list
//! builtins. Online: list/show/create/update/delete/render against the VTA.
//!
//! # Output style
//!
//! Follows the workspace CLI style guide: **list operations emit a ratatui
//! table**, **detail views emit aligned key-value lines**, **actions emit a
//! short `✓`-prefixed confirmation**. See `docs/04-reference/cli-style.md`.

use std::collections::HashMap;
use std::path::PathBuf;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Cell, Row, Table};
use vta_sdk::did_templates::{BUILTIN_NAMES, DidTemplate, load_embedded};
use vta_sdk::prelude::*;

use crate::duration::format_local_time;
use crate::render::{
    CYAN, DIM, GREEN, RED, RESET, YELLOW, is_full_display, print_full_entry, print_full_list_title,
    print_widget,
};

/// `pnm did-templates validate <file>` / `cnm did-templates validate <file>`.
///
/// Loads a template JSON file, runs the structural + semantic validator, and
/// reports pass/fail. Never touches the network.
pub fn cmd_validate(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match DidTemplate::load_file(&path) {
        Ok(tpl) => {
            println!(
                "{GREEN}\u{2713}{RESET} Template {CYAN}'{}'{RESET} ({DIM}{}{RESET}) is valid.",
                tpl.name, tpl.kind
            );
            println!("  schemaVersion: {}", tpl.schema_version);
            if let Some(desc) = &tpl.description {
                println!("  description:   {desc}");
            }
            if !tpl.methods.is_empty() {
                println!("  methods:       {}", tpl.methods.join(", "));
            }
            if !tpl.required_vars.is_empty() {
                println!("  requiredVars:  {}", tpl.required_vars.join(", "));
            }
            if !tpl.optional_vars.is_empty() {
                let names: Vec<&str> = tpl.optional_vars.keys().map(String::as_str).collect();
                println!("  optionalVars:  {}", names.join(", "));
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("{RED}\u{2717}{RESET} Template validation failed:");
            eprintln!("  {e}");
            Err(format!("invalid template at {}", path.display()).into())
        }
    }
}

/// `pnm did-templates init <kind>` / `cnm did-templates init <kind>`.
///
/// Emit a starter template on stdout by forking an embedded built-in. The
/// operator can redirect to a file, edit, and upload. `kind` is a built-in
/// name (`didcomm-mediator`, `did-hosting-control`, `did-hosting-daemon`,
/// `did-hosting-server`).
pub fn cmd_init(kind: String) -> Result<(), Box<dyn std::error::Error>> {
    // Accept either the exact builtin name, a short alias, or a legacy
    // webvh-* name (resolved via the builtin loader's alias table).
    let builtin_name = match kind.as_str() {
        "mediator" => "didcomm-mediator",
        "agent" => "ai-agent",
        "did-hosting" | "hosting" | "daemon" => "did-hosting-daemon",
        "control" => "did-hosting-control",
        "witness" | "watcher" | "server" => "did-hosting-server",
        // Legacy aliases — silently resolve to the renamed templates.
        "webvh-hosting" => "did-hosting-daemon",
        "webvh-control" => "did-hosting-control",
        "webvh-daemon" => "did-hosting-daemon",
        "webvh-server" => "did-hosting-server",
        other if BUILTIN_NAMES.contains(&other) => other,
        other => {
            eprintln!(
                "{RED}\u{2717}{RESET} Unknown builtin kind '{other}'. Available: {}",
                BUILTIN_NAMES.join(", ")
            );
            return Err("unknown builtin".into());
        }
    };

    // Load the builtin, re-serialize as pretty-printed JSON for editing.
    let tpl = load_embedded(builtin_name)?;
    let pretty = serde_json::to_string_pretty(&tpl)?;
    println!("{pretty}");

    // Hint goes to stderr so stdout stays redirect-friendly.
    eprintln!();
    eprintln!(
        "{YELLOW}Tip:{RESET} redirect to a file and edit the {DIM}name{RESET}, {DIM}description{RESET},"
    );
    eprintln!("     and any placeholder values before uploading. For example:");
    eprintln!("       pnm did-templates init {kind} > my-{builtin_name}.json");
    Ok(())
}

// ── Online (global scope — Phase 2; context scope — Phase 3) ────────

fn scope_label(context: Option<&str>) -> String {
    context
        .map(|c| format!("context '{c}'"))
        .unwrap_or_else(|| "global".into())
}

/// `pnm did-templates list [--context X]` — show stored templates.
///
/// Without `--context`, lists global-scope templates. With `--context X`,
/// lists templates scoped to that context. Built-ins are not merged in —
/// use `list-builtins`. Keeping scopes visually distinct makes it obvious
/// whether a template is cross-context (global), context-local, or
/// embedded.
pub async fn cmd_list(
    client: &VtaClient,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = match context {
        Some(ctx) => client.list_context_did_templates(ctx).await?,
        None => client.list_did_templates().await?,
    };

    if crate::render::is_json_output() {
        crate::render::print_json(&records)?;
        return Ok(());
    }

    if records.is_empty() {
        match context {
            Some(ctx) => println!("No DID templates stored in context '{ctx}'."),
            None => println!("No DID templates stored on the VTA."),
        }
        println!("  {DIM}Scaffold one with{RESET} `pnm did-templates init <kind> > tpl.json`,");
        let create_hint = match context {
            Some(ctx) => format!("pnm did-templates create --context {ctx} --file tpl.json"),
            None => "pnm did-templates create --file tpl.json".into(),
        };
        println!("  {DIM}then{RESET} `{create_hint}`.");
        return Ok(());
    }

    if is_full_display() {
        let title = match context {
            Some(ctx) => format!("DID templates in context '{ctx}'"),
            None => "Stored DID templates (global)".to_string(),
        };
        print_full_list_title(&title, records.len());
        for r in &records {
            let required = if r.template.required_vars.is_empty() {
                "—".to_string()
            } else {
                r.template.required_vars.join(", ")
            };
            let description = r
                .template
                .description
                .clone()
                .unwrap_or_else(|| "—".to_string());
            let created = format_local_time(r.created_at);
            print_full_entry(&[
                ("Name", &r.template.name),
                ("Kind", &r.template.kind),
                ("Description", &description),
                ("Required vars", &required),
                ("Created", &created),
                ("Created by", &r.created_by),
            ]);
        }
        return Ok(());
    }

    let dim = Style::default().fg(Color::DarkGray);
    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["Name", "Kind", "Required vars", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = records
        .iter()
        .map(|r| {
            let required = if r.template.required_vars.is_empty() {
                "\u{2014}".to_string()
            } else {
                r.template.required_vars.join(", ")
            };
            let created = format_local_time(r.created_at);
            Row::new(vec![
                Cell::from(r.template.name.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(r.template.kind.clone()),
                Cell::from(required).style(dim),
                Cell::from(created).style(dim),
            ])
        })
        .collect();

    let title = match context {
        Some(ctx) => format!(" DID templates in context '{ctx}' ({}) ", records.len()),
        None => format!(" Stored DID templates (global) ({}) ", records.len()),
    };
    let table = Table::new(
        rows,
        [
            Constraint::Min(24),    // Name
            Constraint::Length(16), // Kind
            Constraint::Min(24),    // Required vars
            Constraint::Length(26), // Created (local tz with offset)
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(Block::bordered().title(title).border_style(dim));

    let height = records.len() as u16 + 4;
    print_widget(table, height);
    Ok(())
}

/// `pnm did-templates show <name> [--context X] [--rendered --var K=V ...]` —
/// fetch one template, optionally rendered.
pub async fn cmd_show(
    client: &VtaClient,
    name: &str,
    context: Option<&str>,
    rendered: bool,
    vars: Vec<(String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if rendered {
        let mut vars_map: HashMap<String, serde_json::Value> = HashMap::new();
        for (k, v) in vars {
            vars_map.insert(k, serde_json::Value::String(v));
        }
        // DID / SIGNING_KEY_MB / KA_KEY_MB are reserved ambient vars the
        // server will fill from Phase 4 onward. Until then, supply them via
        // --var to preview what a rendered document will look like.
        let doc = match context {
            Some(ctx) => {
                client
                    .render_context_did_template(ctx, name, vars_map)
                    .await?
            }
            None => client.render_did_template(name, vars_map).await?,
        };
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    let r = match context {
        Some(ctx) => client.get_context_did_template(ctx, name).await?,
        None => client.get_did_template(name).await?,
    };
    let pretty = serde_json::to_string_pretty(&r)?;
    println!("{pretty}");
    Ok(())
}

/// `pnm did-templates create --file <path> [--context X]` — upload a template.
///
/// The file is validated locally before upload so authoring errors fail
/// fast without burning a round-trip to a super-admin ACL check.
pub async fn cmd_create(
    client: &VtaClient,
    context: Option<&str>,
    file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let tpl = DidTemplate::load_file(&file)
        .map_err(|e| format!("template at {} is invalid: {e}", file.display()))?;
    let record = match context {
        Some(ctx) => client.create_context_did_template(ctx, tpl).await?,
        None => client.create_did_template(tpl).await?,
    };
    println!(
        "{GREEN}\u{2713}{RESET} Created {CYAN}'{}'{RESET} ({DIM}{}{RESET}) in {}.",
        record.template.name,
        record.template.kind,
        scope_label(context)
    );
    Ok(())
}

/// `pnm did-templates update <name> --file <path> [--context X]` — replace a template.
pub async fn cmd_update(
    client: &VtaClient,
    name: &str,
    context: Option<&str>,
    file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let tpl = DidTemplate::load_file(&file)
        .map_err(|e| format!("template at {} is invalid: {e}", file.display()))?;
    if tpl.name != name {
        return Err(format!(
            "file's template name '{}' does not match --name argument '{}'",
            tpl.name, name
        )
        .into());
    }
    let record = match context {
        Some(ctx) => client.update_context_did_template(ctx, name, tpl).await?,
        None => client.update_did_template(name, tpl).await?,
    };
    println!(
        "{GREEN}\u{2713}{RESET} Updated {CYAN}'{}'{RESET} in {}.",
        record.template.name,
        scope_label(context)
    );
    Ok(())
}

/// `pnm did-templates export <name> [--context X]` — emit a portable JSON
/// file of a stored template, stripping server provenance (scope, timestamps,
/// author DID). The output shape matches what `init` emits, so `export | edit
/// | create --file -` round-trips without a format conversion step.
///
/// Writes to stdout so operators can redirect to a file or pipe through
/// `jq`/`diff`. Never audits.
pub async fn cmd_export(
    client: &VtaClient,
    name: &str,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = match context {
        Some(ctx) => client.get_context_did_template(ctx, name).await?,
        None => client.get_did_template(name).await?,
    };
    let pretty = serde_json::to_string_pretty(&record.template)?;
    println!("{pretty}");
    Ok(())
}

/// `pnm did-templates diff <name> --file <path> [--context X]` — compare a
/// local template file against what the VTA has stored. Walks the parsed JSON
/// in parallel and reports every path whose value differs.
///
/// Exits non-zero when the two templates differ, so the command plugs into
/// scripts ("is my local copy in sync?"). No changes → exit 0, silent stdout.
pub async fn cmd_diff(
    client: &VtaClient,
    name: &str,
    context: Option<&str>,
    file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load local first — if the file is malformed, fail fast without burning
    // a round-trip.
    let local = DidTemplate::load_file(&file)
        .map_err(|e| format!("local template at {} is invalid: {e}", file.display()))?;

    let remote_record = match context {
        Some(ctx) => client.get_context_did_template(ctx, name).await?,
        None => client.get_did_template(name).await?,
    };
    let remote = remote_record.template;

    let remote_val = serde_json::to_value(&remote)?;
    let local_val = serde_json::to_value(&local)?;

    let mut differences = Vec::new();
    walk_json_diff("", &remote_val, &local_val, &mut differences);

    if differences.is_empty() {
        println!(
            "{GREEN}\u{2713}{RESET} Local {CYAN}'{name}'{RESET} matches stored {}.",
            scope_label(context)
        );
        return Ok(());
    }

    println!(
        "{YELLOW}Differences{RESET} between stored {CYAN}'{name}'{RESET} ({}) and {}:",
        scope_label(context),
        file.display()
    );
    println!("  {DIM}(\u{2212} stored, + local){RESET}");
    for line in &differences {
        println!("{line}");
    }
    Err(format!("{} field(s) differ", differences.len()).into())
}

/// Recursive JSON walker that reports every leaf path where `remote` and
/// `local` disagree. Arrays are compared element-wise; length mismatches
/// are reported as a single line.
fn walk_json_diff(
    path: &str,
    remote: &serde_json::Value,
    local: &serde_json::Value,
    out: &mut Vec<String>,
) {
    use serde_json::Value;
    match (remote, local) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: std::collections::BTreeSet<&String> = a.keys().collect();
            keys.extend(b.keys());
            for key in keys {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match (a.get(key), b.get(key)) {
                    (Some(av), Some(bv)) => walk_json_diff(&child_path, av, bv, out),
                    (Some(av), None) => {
                        out.push(format!("  {RED}\u{2212}{RESET} {child_path} = {av}"));
                    }
                    (None, Some(bv)) => {
                        out.push(format!("  {GREEN}+{RESET} {child_path} = {bv}"));
                    }
                    (None, None) => unreachable!(),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                out.push(format!(
                    "  {YELLOW}~{RESET} {path}: array length {} \u{2192} {}",
                    a.len(),
                    b.len()
                ));
                return;
            }
            for (i, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
                walk_json_diff(&format!("{path}[{i}]"), av, bv, out);
            }
        }
        (a, b) if a == b => {}
        (a, b) => {
            out.push(format!(
                "  {RED}\u{2212}{RESET} {path} = {a}\n  {GREEN}+{RESET} {path} = {b}"
            ));
        }
    }
}

/// `pnm did-templates delete <name> [--context X]` — remove a stored template.
pub async fn cmd_delete(
    client: &VtaClient,
    name: &str,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match context {
        Some(ctx) => client.delete_context_did_template(ctx, name).await?,
        None => client.delete_did_template(name).await?,
    }
    println!(
        "{GREEN}\u{2713}{RESET} Deleted {CYAN}'{name}'{RESET} from {}.",
        scope_label(context)
    );
    Ok(())
}

// ── Offline (Phase 1 helpers) ───────────────────────────────────────

/// `pnm did-templates list-builtins`.
///
/// Show the names of every built-in template shipped with this SDK.
pub fn cmd_list_builtins() -> Result<(), Box<dyn std::error::Error>> {
    let dim = Style::default().fg(Color::DarkGray);
    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["Name", "Kind", "Required vars", "Description"])
        .style(header_style)
        .bottom_margin(1);

    let mut rows: Vec<Row> = Vec::with_capacity(BUILTIN_NAMES.len());
    for name in BUILTIN_NAMES {
        let tpl = load_embedded(name)?;
        let required = if tpl.required_vars.is_empty() {
            "\u{2014}".to_string()
        } else {
            tpl.required_vars.join(", ")
        };
        let description = tpl.description.clone().unwrap_or_else(|| "\u{2014}".into());
        rows.push(Row::new(vec![
            Cell::from(name.to_string()).style(Style::default().fg(Color::Cyan)),
            Cell::from(tpl.kind),
            Cell::from(required).style(dim),
            Cell::from(description),
        ]));
    }

    let title = format!(" Built-in DID templates ({}) ", BUILTIN_NAMES.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(24), // Name
            Constraint::Length(16), // Kind
            Constraint::Length(24), // Required vars
            Constraint::Min(40),    // Description
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(Block::bordered().title(title).border_style(dim));

    let height = BUILTIN_NAMES.len() as u16 + 4;
    print_widget(table, height);
    Ok(())
}
