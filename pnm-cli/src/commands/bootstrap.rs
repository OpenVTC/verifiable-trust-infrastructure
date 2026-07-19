//! Dispatch for `pnm bootstrap …`.
//!
//! Bootstrap is split across two main-loop phases:
//!
//! - [`run_offline`] handles `request`, `open`, `connect`, and
//!   `provision-request` — none of which need an authenticated
//!   `VtaClient`. It returns `None` when the subcommand is the
//!   authenticated `provision-integration`, signalling the caller
//!   to fall through to the post-auth dispatch.
//! - [`run_authed`] handles `provision-integration`, which bridges
//!   to a JWT-gated REST endpoint.

use vta_sdk::client::VtaClient;

use crate::bootstrap;
use crate::cli::BootstrapCommands;
use crate::config::PnmConfig;

pub(crate) async fn run_offline(
    command: &BootstrapCommands,
    pnm_config: &mut PnmConfig,
) -> Option<Result<(), Box<dyn std::error::Error>>> {
    match command {
        BootstrapCommands::Request { out, label } => {
            Some(bootstrap::run_request(out.clone(), label.clone()).await)
        }
        BootstrapCommands::Open {
            bundle,
            out,
            expect_digest,
            no_verify_digest,
            expect_vta_did,
        } => Some(
            bootstrap::run_open(
                bundle.clone(),
                out.clone(),
                expect_digest.clone(),
                *no_verify_digest,
                expect_vta_did.clone(),
            )
            .await,
        ),
        BootstrapCommands::Connect {
            vta_url,
            expect_digest,
            no_verify_digest,
            expect_pcr0,
            expect_pcr8,
            slug,
        } => Some(
            bootstrap::run_connect(
                vta_url.clone(),
                expect_digest.clone(),
                *no_verify_digest,
                expect_pcr0.clone(),
                expect_pcr8.clone(),
                slug.clone(),
                pnm_config,
            )
            .await,
        ),
        BootstrapCommands::ProvisionRequest {
            template,
            vars,
            context_hint,
            admin_template,
            validity_hours,
            label,
            out,
        } => Some(
            bootstrap::run_provision_request(
                template.clone(),
                vars.clone(),
                context_hint.clone(),
                admin_template.clone(),
                *validity_hours,
                label.clone(),
                out.clone(),
            )
            .await,
        ),
        // Authed — handled by `run_authed`.
        BootstrapCommands::ProvisionIntegration { .. } => None,
    }
}

pub(crate) async fn run_authed(
    client: &VtaClient,
    command: BootstrapCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        BootstrapCommands::ProvisionIntegration {
            request,
            context,
            assertion,
            vc_validity_seconds,
            out,
            create_context,
        } => {
            bootstrap::run_provision_integration(
                client,
                request,
                context,
                assertion,
                vc_validity_seconds,
                out,
                create_context,
            )
            .await
        }
        BootstrapCommands::Request { .. }
        | BootstrapCommands::Open { .. }
        | BootstrapCommands::Connect { .. }
        | BootstrapCommands::ProvisionRequest { .. } => unreachable!(
            "offline bootstrap subcommands run via run_offline; reaching run_authed is a bug"
        ),
    }
}
