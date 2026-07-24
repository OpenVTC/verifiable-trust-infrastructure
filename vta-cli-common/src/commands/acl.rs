use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::acl::ApproveScope;
use vta_sdk::prelude::*;
use vti_common::acl::{Role, act_scope_for};

use crate::display::{
    NAME_HEADER, NameBook, NameSource, book_from_acl, did_cell, full_display_pairs, name_cell,
    named_did_cell, resolve_agent_names_into,
};
use crate::render::{is_full_display, print_full_entry_owned, print_full_list_title, print_widget};

/// Human-readable context list — **role-aware**, because an empty
/// `allowed_contexts` means opposite things depending on the role.
///
/// `AuthClaims::is_super_admin` requires `Role::Admin` *and* an empty list;
/// `has_context_access` otherwise iterates `allowed_contexts`, and an empty
/// list matches nothing. So empty means "every context" for an admin and
/// "no context at all" for every other role.
///
/// Rendering both as `(unrestricted)` misled in both directions on a
/// security-relevant display: a correctly-scoped least-privilege approver
/// looked like a blanket grant, and an operator auditing for over-broad
/// access saw `(unrestricted)` on rows that were in fact inert.
pub fn format_contexts(role: &str, contexts: &[String]) -> String {
    // The wire form carries the role as a string, so parse it back before
    // decoding. An unrecognised role falls to the most restrictive reading:
    // a display must never invent authority it cannot confirm.
    //
    // `format_role` already renders an unrestricted admin as "super admin", so
    // the two columns read together without repeating the term.
    let role = Role::parse(role).unwrap_or(Role::Monitor);
    act_scope_for(&role, contexts).to_string()
}

pub fn format_role(role: &str, contexts: &[String]) -> String {
    if role == "admin" && contexts.is_empty() {
        "super admin".to_string()
    } else {
        role.to_string()
    }
}

/// Human-readable approve-authority — what this entry may *confer* via an
/// approval (task-consent delegation / step-up ratification) while acting
/// nowhere. `None` when it confers nothing, so callers omit the line entirely.
pub fn format_approve_scope(approve_all: bool, approve_contexts: &[String]) -> Option<String> {
    if approve_all {
        Some("all contexts".to_string())
    } else if !approve_contexts.is_empty() {
        Some(format!("contexts [{}]", approve_contexts.join(", ")))
    } else {
        None
    }
}

pub fn validate_role(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    match role {
        "admin" | "initiator" | "application" | "reader" => Ok(()),
        _ => Err(format!(
            "invalid role '{role}', expected: admin, initiator, application, or reader"
        )
        .into()),
    }
}

pub async fn cmd_acl_list(
    client: &VtaClient,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_acl(context).await?;

    // `--json` short-circuits all rendering and emits a single JSON
    // document. Empty result returns an empty array, NOT a printed
    // "no entries" string — automation scripts depend on the JSON
    // shape being consistent across populated and empty results.
    if crate::render::is_json_output() {
        crate::render::print_json(&resp.entries)?;
        return Ok(());
    }

    if resp.entries.is_empty() {
        println!("No ACL entries found.");
        return Ok(());
    }

    // One pass over the entries names every subject from its label — and,
    // for free, the `Created By` column too, since a granting admin nearly
    // always holds an ACL entry of their own.
    let mut book = NameBook::new();
    book_from_acl(&mut book, &resp.entries);
    // Opt-in, and only over the DIDs actually on screen — including the
    // `created_by` column, which is where an unfamiliar DID most often shows up.
    resolve_agent_names_into(
        &mut book,
        resp.entries
            .iter()
            .flat_map(|e| [e.did.as_str(), e.created_by.as_str()]),
    )
    .await;

    if is_full_display() {
        print_full_list_title("ACL Entries", resp.entries.len());
        for entry in &resp.entries {
            let contexts = format_contexts(&entry.role, &entry.allowed_contexts);
            let role = format_role(&entry.role, &entry.allowed_contexts);
            let approve = format_approve_scope(entry.approve_all_contexts, &entry.approve_contexts);

            // Name + full DID. Full display exists so an operator can copy a
            // complete identifier, so the DID is never abbreviated here.
            let mut fields = full_display_pairs(&book, &entry.did);
            fields.push(("Role", role));
            // The raw label is normally what the Name line already shows; keep
            // it only when something higher-ranked (an agent name) displaced it.
            if let Some(label) = entry.label.as_deref()
                && book.name_of(&entry.did).as_deref() != Some(label)
            {
                fields.push(("Label", label.to_string()));
            }
            fields.push(("Contexts", contexts));
            if let Some(a) = approve {
                fields.push(("Approve", a));
            }
            fields.push(("Created By", book.render_inline(&entry.created_by)));
            print_full_entry_owned(&fields);
        }
        return Ok(());
    }

    // Only give up a column to names if at least one entry has one — on a VTA
    // where nothing has been labelled, a column of dashes is worse than no
    // column.
    let show_names = book.names_any(resp.entries.iter().map(|e| e.did.as_str()));

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let mut header_cells = vec!["DID", "Role", "Contexts", "Created By"];
    if show_names {
        header_cells.insert(0, NAME_HEADER);
    }
    let header = Row::new(header_cells).style(header_style).bottom_margin(1);

    let rows: Vec<Row> = resp
        .entries
        .iter()
        .map(|entry| {
            let contexts = format_contexts(&entry.role, &entry.allowed_contexts);
            let mut cells = vec![
                did_cell(&entry.did),
                Cell::from(format_role(&entry.role, &entry.allowed_contexts)),
                Cell::from(contexts),
                named_did_cell(&book, &entry.created_by),
            ];
            if show_names {
                cells.insert(0, name_cell(&book, &entry.did));
            }
            Row::new(cells)
        })
        .collect();

    let title = format!(" ACL Entries ({}) ", resp.entries.len());

    // DIDs are abbreviated by `shorten_did` (SCID squeezed, domain tail kept),
    // which frees the width the name column needs. `--full-display` and
    // `--json` still carry every DID in full.
    let mut constraints = vec![
        Constraint::Min(34),    // DID
        Constraint::Length(12), // Role
        Constraint::Length(24), // Contexts
        Constraint::Min(30),    // Created By
    ];
    if show_names {
        constraints.insert(0, Constraint::Min(16));
    }

    let table = Table::new(rows, constraints)
        .header(header)
        .column_spacing(2)
        .block(
            Block::bordered()
                .title(title)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

    let height = resp.entries.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_acl_get(client: &VtaClient, did: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = client.get_acl(did).await?;

    let mut book = NameBook::new();
    book.insert_opt(&entry.did, entry.label.as_deref(), NameSource::AclLabel);
    resolve_agent_names_into(&mut book, [entry.did.as_str()]).await;

    // Name above DID, DID in full — a single-entry view is where an operator
    // copies an identifier from.
    match book.name_of(&entry.did) {
        Some(name) => {
            println!("Name:             {name}");
            println!("DID:              {}", entry.did);
        }
        None => println!("DID:              {}", entry.did),
    }
    println!(
        "Role:             {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    // Normally the Name line above; shown separately only when something
    // higher-ranked (a verified agent name) displaced the operator's label.
    if let Some(label) = entry.label.as_deref()
        && book.name_of(&entry.did).as_deref() != Some(label)
    {
        println!("Label:            {label}");
    }
    println!(
        "Contexts:         {}",
        format_contexts(&entry.role, &entry.allowed_contexts)
    );
    if let Some(scope) = format_approve_scope(entry.approve_all_contexts, &entry.approve_contexts) {
        println!("Approve:          {scope}");
    }
    println!("Created At:       {}", entry.created_at);
    println!("Created By:       {}", entry.created_by);
    Ok(())
}

pub async fn cmd_acl_create(
    client: &VtaClient,
    did: String,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
    expires_at: Option<u64>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
    approve_all: bool,
    approve_contexts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_role(&role)?;
    let mut req = CreateAclRequest::new(did, role).contexts(contexts);
    if let Some(l) = label {
        req = req.label(l);
    }
    if let Some(secs) = expires_at {
        req = req.expires_at(secs);
    }
    if let Some(ref approver) = step_up_approver {
        req = req.step_up_approver(approver.clone());
    }
    if let Some(ref require) = step_up_require {
        req = req.step_up_require(require.clone());
    }
    if approve_all {
        req = req.approve_all();
    } else if !approve_contexts.is_empty() {
        req = req.approve_contexts(approve_contexts);
    }
    let entry = client.create_acl(req).await?;
    println!("ACL entry created:");
    println!("  DID:        {}", entry.did);
    println!(
        "  Role:       {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    if let Some(label) = &entry.label {
        println!("  Label:      {label}");
    }
    println!(
        "  Contexts:   {}",
        format_contexts(&entry.role, &entry.allowed_contexts)
    );
    if let Some(scope) = format_approve_scope(entry.approve_all_contexts, &entry.approve_contexts) {
        println!("  Approve:    {scope}");
    }
    if let Some(approver) = &step_up_approver {
        println!("  Step-up approver: {approver}");
    }
    if let Some(require) = &step_up_require {
        println!("  Step-up require:  {require}");
    }
    match entry.expires_at {
        Some(secs) => println!(
            "  Expires at: {} ({})",
            crate::duration::format_local_time(secs),
            crate::duration::format_remaining(secs),
        ),
        None => println!("  Expires at: (permanent)"),
    }
    Ok(())
}

/// Resolve the three mutually-exclusive approve flags into the wire value.
///
/// `None` means "leave unchanged" — which is why revoking needs its own flag
/// rather than an empty `--approve-contexts`: an empty list cannot mean both
/// "confer nothing" and "don't touch it".
pub fn approve_scope_from_flags(
    approve_all: bool,
    approve_contexts: Option<Vec<String>>,
    approve_none: bool,
) -> Option<ApproveScope> {
    if approve_none {
        Some(ApproveScope::None)
    } else if approve_all {
        Some(ApproveScope::All)
    } else {
        approve_contexts.map(ApproveScope::Contexts)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_acl_update(
    client: &VtaClient,
    did: &str,
    role: Option<String>,
    label: Option<String>,
    contexts: Option<Vec<String>>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
    approve_scope: Option<ApproveScope>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref r) = role {
        validate_role(r)?;
    }
    let approve_scope_echo = approve_scope.clone();
    let req = UpdateAclRequest {
        role,
        label,
        allowed_contexts: contexts,
        step_up_approver: step_up_approver.clone(),
        step_up_require: step_up_require.clone(),
        approve_scope,
    };
    let entry = client.update_acl(did, req).await?;
    println!("ACL entry updated:");
    println!("  DID:      {}", entry.did);
    println!(
        "  Role:     {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    if let Some(label) = &entry.label {
        println!("  Label:    {label}");
    }
    println!(
        "  Contexts: {}",
        format_contexts(&entry.role, &entry.allowed_contexts)
    );
    if let Some(approver) = &step_up_approver {
        if approver.is_empty() {
            println!("  Step-up approver: (cleared)");
        } else {
            println!("  Step-up approver: {approver}");
        }
    }
    if let Some(require) = &step_up_require {
        if require.is_empty() {
            println!("  Step-up require:  (cleared)");
        } else {
            println!("  Step-up require:  {require}");
        }
    }
    // Echo the scope only when this call set it, so "unchanged" is visibly
    // different from "set to confer nothing".
    if let Some(scope) = &approve_scope_echo {
        let rendered = match scope {
            ApproveScope::None => "(revoked — confers nothing)".to_string(),
            ApproveScope::All => "all contexts".to_string(),
            ApproveScope::Contexts(cs) => format!("contexts [{}]", cs.join(", ")),
        };
        println!("  Approve:  {rendered}");
    }
    Ok(())
}

pub async fn cmd_acl_delete(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_acl(did).await?;
    println!("ACL entry deleted: {did}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_contexts ────────────────────────────────────────────

    /// Empty means "every context" only for an admin. This test previously
    /// asserted `(unrestricted)` for an empty list regardless of role, which
    /// pinned the bug rather than the behaviour.
    #[test]
    fn test_format_contexts_empty_is_role_dependent() {
        assert_eq!(format_contexts("admin", &[]), "(unrestricted)");
        for role in ["reader", "initiator", "application"] {
            assert_eq!(
                format_contexts(role, &[]),
                "(none — acts nowhere)",
                "empty contexts must not read as unrestricted for role {role}"
            );
        }
    }

    /// The shape the `--approve-all` help text itself recommends: a reader
    /// with no contexts whose authority is entirely `approve_scope`. It acts
    /// nowhere, and the display must not suggest otherwise.
    #[test]
    fn test_least_privilege_approver_does_not_read_as_unrestricted() {
        let contexts: Vec<String> = vec![];
        assert_eq!(
            format_contexts("reader", &contexts),
            "(none — acts nowhere)"
        );
        assert_eq!(format_role("reader", &contexts), "reader");
        assert_eq!(
            format_approve_scope(false, &["openvtc".to_string()]).as_deref(),
            Some("contexts [openvtc]")
        );
    }

    #[test]
    fn test_format_approve_scope() {
        assert_eq!(
            format_approve_scope(true, &[]).as_deref(),
            Some("all contexts")
        );
        assert_eq!(
            format_approve_scope(false, &["openvtc".to_string()]).as_deref(),
            Some("contexts [openvtc]")
        );
        assert_eq!(
            format_approve_scope(false, &["a".to_string(), "b".to_string()]).as_deref(),
            Some("contexts [a, b]")
        );
        // Confers nothing ⇒ no line.
        assert_eq!(format_approve_scope(false, &[]), None);
    }

    #[test]
    fn test_format_contexts_single() {
        let ctx = vec!["vta".to_string()];
        assert_eq!(format_contexts("reader", &ctx), "vta");
    }

    #[test]
    fn test_format_contexts_multiple() {
        let ctx = vec!["vta".to_string(), "payments".to_string()];
        assert_eq!(format_contexts("reader", &ctx), "vta, payments");
    }

    // ── format_role ────────────────────────────────────────────────

    #[test]
    fn test_format_role_admin_no_contexts_is_super_admin() {
        assert_eq!(format_role("admin", &[]), "super admin");
    }

    #[test]
    fn test_format_role_admin_with_contexts_stays_admin() {
        let ctx = vec!["vta".to_string()];
        assert_eq!(format_role("admin", &ctx), "admin");
    }

    #[test]
    fn test_format_role_initiator_unchanged() {
        assert_eq!(format_role("initiator", &[]), "initiator");
    }

    #[test]
    fn test_format_role_application_unchanged() {
        let ctx = vec!["app".to_string()];
        assert_eq!(format_role("application", &ctx), "application");
    }

    // ── validate_role ──────────────────────────────────────────────

    #[test]
    fn test_validate_role_admin_ok() {
        assert!(validate_role("admin").is_ok());
    }

    #[test]
    fn test_validate_role_initiator_ok() {
        assert!(validate_role("initiator").is_ok());
    }

    #[test]
    fn test_validate_role_application_ok() {
        assert!(validate_role("application").is_ok());
    }

    #[test]
    fn test_validate_role_reader_ok() {
        assert!(validate_role("reader").is_ok());
    }

    #[test]
    fn test_validate_role_unknown_fails() {
        let err = validate_role("superuser").unwrap_err();
        assert!(err.to_string().contains("invalid role 'superuser'"));
    }

    #[test]
    fn test_validate_role_empty_fails() {
        assert!(validate_role("").is_err());
    }
}
