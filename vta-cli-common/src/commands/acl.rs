use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::prelude::*;

use crate::render::{is_full_display, print_full_entry, print_full_list_title, print_widget};

pub fn format_contexts(contexts: &[String]) -> String {
    if contexts.is_empty() {
        "(unrestricted)".to_string()
    } else {
        contexts.join(", ")
    }
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

    if is_full_display() {
        print_full_list_title("ACL Entries", resp.entries.len());
        for entry in &resp.entries {
            let label = entry.label.as_deref().unwrap_or("—");
            let contexts = format_contexts(&entry.allowed_contexts);
            let role = format_role(&entry.role, &entry.allowed_contexts);
            let approve = format_approve_scope(entry.approve_all_contexts, &entry.approve_contexts);
            let mut fields: Vec<(&str, &str)> = vec![
                ("DID", &entry.did),
                ("Role", &role),
                ("Label", label),
                ("Contexts", &contexts),
            ];
            if let Some(a) = &approve {
                fields.push(("Approve", a));
            }
            fields.push(("Created By", &entry.created_by));
            print_full_entry(&fields);
        }
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["DID", "Role", "Label", "Contexts", "Created By"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .entries
        .iter()
        .map(|entry| {
            let label = entry.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let contexts = format_contexts(&entry.allowed_contexts);

            Row::new(vec![
                Cell::from(entry.did.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(format_role(&entry.role, &entry.allowed_contexts)),
                Cell::from(label),
                Cell::from(contexts),
                Cell::from(entry.created_by.clone()).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" ACL Entries ({}) ", resp.entries.len());

    // `Created By` and `DID` hold full did:key values (~57 chars); use
    // `Min` rather than fixed `Length` so they expand on wide terminals
    // instead of truncating. Role / Contexts are short and bounded.
    let table = Table::new(
        rows,
        [
            Constraint::Min(60),    // DID
            Constraint::Length(12), // Role
            Constraint::Min(16),    // Label
            Constraint::Length(24), // Contexts
            Constraint::Min(52),    // Created By
        ],
    )
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
    println!("DID:              {}", entry.did);
    println!(
        "Role:             {}",
        format_role(&entry.role, &entry.allowed_contexts)
    );
    println!(
        "Label:            {}",
        entry.label.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Contexts:         {}",
        format_contexts(&entry.allowed_contexts)
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
    println!("  Contexts:   {}", format_contexts(&entry.allowed_contexts));
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

pub async fn cmd_acl_update(
    client: &VtaClient,
    did: &str,
    role: Option<String>,
    label: Option<String>,
    contexts: Option<Vec<String>>,
    step_up_approver: Option<String>,
    step_up_require: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref r) = role {
        validate_role(r)?;
    }
    let req = UpdateAclRequest {
        role,
        label,
        allowed_contexts: contexts,
        step_up_approver: step_up_approver.clone(),
        step_up_require: step_up_require.clone(),
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
    println!("  Contexts: {}", format_contexts(&entry.allowed_contexts));
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

    #[test]
    fn test_format_contexts_empty_shows_unrestricted() {
        assert_eq!(format_contexts(&[]), "(unrestricted)");
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
        assert_eq!(format_contexts(&ctx), "vta");
    }

    #[test]
    fn test_format_contexts_multiple() {
        let ctx = vec!["vta".to_string(), "payments".to_string()];
        assert_eq!(format_contexts(&ctx), "vta, payments");
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
