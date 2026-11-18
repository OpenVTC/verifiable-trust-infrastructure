//! Dispatch for `pnm did-templates …`.
//!
//! Split into [`run_offline`] (Validate / Init / ListBuiltins — never
//! contacts the VTA) and [`run_online`] (every other arm — needs an
//! authenticated `VtaClient`). [`crate::cli::is_online_template_cmd`]
//! is the single source of truth for which arm a given variant lands in.

use vta_cli_common::commands::did_templates;
use vta_sdk::client::VtaClient;

use crate::cli::DidTemplateCommands;

pub(crate) fn run_offline(command: &DidTemplateCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DidTemplateCommands::Validate { file } => did_templates::cmd_validate(file.clone()),
        DidTemplateCommands::Init { kind } => did_templates::cmd_init(kind.clone()),
        DidTemplateCommands::ListBuiltins => did_templates::cmd_list_builtins(),
        // Online subcommands fall through to `run_online`; the
        // `requires_auth` guard routes them there.
        _ => unreachable!("online did-templates run post-auth"),
    }
}

pub(crate) async fn run_online(
    client: &VtaClient,
    command: DidTemplateCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DidTemplateCommands::Validate { .. }
        | DidTemplateCommands::Init { .. }
        | DidTemplateCommands::ListBuiltins => unreachable!("offline commands run pre-auth"),
        DidTemplateCommands::List { context } => {
            did_templates::cmd_list(client, context.as_deref()).await
        }
        DidTemplateCommands::Show {
            name,
            context,
            rendered,
            vars,
        } => did_templates::cmd_show(client, &name, context.as_deref(), rendered, vars).await,
        DidTemplateCommands::Create { file, context } => {
            did_templates::cmd_create(client, context.as_deref(), file).await
        }
        DidTemplateCommands::Update {
            name,
            file,
            context,
        } => did_templates::cmd_update(client, &name, context.as_deref(), file).await,
        DidTemplateCommands::Delete { name, context, yes } => {
            if !vta_cli_common::confirm::confirm_or_cancel(
                &format!("delete the stored template `{name}`"),
                yes,
            )? {
                return Ok(());
            }
            did_templates::cmd_delete(client, &name, context.as_deref()).await
        }
        DidTemplateCommands::Export { name, context } => {
            did_templates::cmd_export(client, &name, context.as_deref()).await
        }
        DidTemplateCommands::Diff {
            name,
            file,
            context,
        } => did_templates::cmd_diff(client, &name, context.as_deref(), file).await,
    }
}
