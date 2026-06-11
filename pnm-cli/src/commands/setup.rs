//! Dispatch for `pnm setup …`.
//!
//! Routes the (subcommand, --name) pair into the four supported phases
//! exposed by [`crate::setup`]. Conflict detection (`--name` paired with
//! `continue`) lives here so operators get a targeted error rather than
//! clap's generic "argument conflict" message.

use crate::cli::SetupCommands;
use crate::config::PnmConfig;
use crate::setup;

pub(crate) async fn run(
    pnm_config: &mut PnmConfig,
    command: Option<SetupCommands>,
    name: Option<String>,
    overwrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match (command, name) {
        (
            Some(SetupCommands::Continue {
                slug,
                vta_did: None,
                ..
            }),
            None,
        ) => setup::continue_non_tee_setup_interactive(pnm_config, &slug).await,
        (
            Some(SetupCommands::Continue {
                slug,
                vta_did: Some(vta_did),
                vta_url,
                mediator_did,
            }),
            None,
        ) => {
            setup::continue_non_tee_setup_non_interactive(
                pnm_config,
                &slug,
                &vta_did,
                vta_url.as_deref(),
                mediator_did.as_deref(),
            )
            .await
        }
        (None, Some(name)) => {
            setup::start_non_tee_setup_non_interactive(pnm_config, &name, overwrite).await
        }
        (None, None) => setup::run_setup(setup::SetupOptions {}, pnm_config).await,
        (Some(_), Some(_)) => Err(
            "conflicting options: `--name` is for phase 1, `continue` is for phase 2 — \
             pass one or the other, not both."
                .into(),
        ),
    }
}
