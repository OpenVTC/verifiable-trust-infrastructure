//! Dispatch for `pnm webs …`.

use vta_cli_common::commands::webs::{self, CreateArgs, UpdateArgs};
use vta_sdk::client::VtaClient;

use crate::cli::WebsCommands;

/// `didcomm`, `tsp`, `didcomm,tsp` or `none` as the `(mediator, tsp)` set.
fn service_set(s: &str) -> Result<(bool, bool), String> {
    let mut set = (false, false);
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part {
            "didcomm" => set.0 = true,
            "tsp" => set.1 = true,
            "none" => {}
            other => {
                return Err(format!(
                    "unknown service `{other}`: use didcomm, tsp, didcomm,tsp or none"
                ));
            }
        }
    }
    Ok(set)
}

pub(crate) async fn run(
    client: &VtaClient,
    command: WebsCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        WebsCommands::Create {
            context,
            server,
            path,
            domain,
            label,
            didcomm,
            tsp,
            also_known_as,
            set_primary,
            class,
            template,
            template_context,
            vars,
        } => {
            webs::cmd_webs_create(
                client,
                CreateArgs {
                    context,
                    server,
                    path,
                    domain,
                    label,
                    didcomm,
                    tsp,
                    also_known_as,
                    set_primary,
                    class,
                    template,
                    template_context,
                    vars,
                },
            )
            .await
        }
        WebsCommands::Get { did, keri_cesr } => webs::cmd_webs_get(client, &did, keri_cesr).await,
        WebsCommands::List {
            context,
            server,
            include_deactivated,
        } => {
            webs::cmd_webs_list(
                client,
                context.as_deref(),
                server.as_deref(),
                include_deactivated,
            )
            .await
        }
        WebsCommands::Update {
            did,
            services,
            rotate_key_agreement,
            also_known_as,
            clear_aliases,
            expect_version,
        } => {
            let services = services.as_deref().map(service_set).transpose()?;
            let also_known_as = if clear_aliases {
                Some(Vec::new())
            } else if also_known_as.is_empty() {
                None
            } else {
                Some(also_known_as)
            };
            webs::cmd_webs_update(
                client,
                UpdateArgs {
                    did,
                    services,
                    rotate_key_agreement,
                    also_known_as,
                    expected_version: expect_version,
                },
            )
            .await
        }
        WebsCommands::Rotate {
            did,
            expect_version,
        } => webs::cmd_webs_rotate(client, &did, expect_version.as_deref()).await,
        WebsCommands::Delete {
            did,
            expect_version,
        } => webs::cmd_webs_delete(client, &did, expect_version.as_deref()).await,
    }
}

#[cfg(test)]
mod tests {
    use super::service_set;

    #[test]
    fn a_service_set_reads_both_flags() {
        assert_eq!(service_set("didcomm,tsp"), Ok((true, true)));
        assert_eq!(service_set("tsp"), Ok((false, true)));
        assert_eq!(service_set("none"), Ok((false, false)));
        assert!(service_set("rest").is_err());
    }
}
