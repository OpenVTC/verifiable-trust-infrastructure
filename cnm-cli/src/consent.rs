//! `cnm consent {show,approve,deny}` — answer the community's consent requests.
//!
//! Making or widening an unrestricted administrator needs another unrestricted
//! administrator's consent (VTI-APV-014). The VTC raises a signed
//! `task-consent/request/0.1` for each approver, pushes it to them, and hands
//! the same documents back to the requester in its refusal
//! (`details.consentRequests`). An approver with a `cnm` profile takes the
//! relayed request and signs the decision here. What is shown and the code
//! comparison approval requires are shared with `pnm consent`
//! ([`vta_cli_common::consent_approve`]).

use std::path::{Path, PathBuf};

use clap::Subcommand;
use vta_cli_common::consent_approve;
use vta_cli_common::render::bin_name;
use vta_sdk::task_consent::VerifiedConsentRequest;
use vtc_client::VtcError;

use crate::vtc::{self, VtcTarget};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum ConsentCommands {
    /// Verify a consent request and show what it asks. Sends nothing.
    Show {
        /// The request: a request document, the requester's refusal body, or
        /// its `details` (`-` reads stdin).
        request: PathBuf,
    },
    /// Approve a consent request, after comparing its match code.
    Approve {
        /// The request: a request document, the requester's refusal body, or
        /// its `details` (`-` reads stdin).
        request: PathBuf,
        /// The code the requester's screen shows. Without it you are asked to
        /// type it; approval never proceeds on a code nobody compared.
        #[arg(long)]
        match_code: Option<String>,
        /// A note recorded with the decision (at most 500 characters).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Deny a consent request. The requester has to ask again.
    Deny {
        /// The request: a request document, the requester's refusal body, or
        /// its `details` (`-` reads stdin).
        request: PathBuf,
        /// Why, recorded with the decision (at most 500 characters).
        #[arg(long)]
        reason: Option<String>,
    },
}

pub async fn run(command: ConsentCommands, keyring_key: &str, target: &VtcTarget) -> CliResult<()> {
    match command {
        ConsentCommands::Show { request } => {
            let verified = load(&request, keyring_key, target).await?;
            consent_approve::render(&verified);
            Ok(())
        }
        ConsentCommands::Approve {
            request,
            match_code,
            reason,
        } => {
            let verified = load(&request, keyring_key, target).await?;
            consent_approve::render(&verified);
            consent_approve::confirm_match_code(&verified, match_code.as_deref(), bin_name())?;
            decide(&verified, true, reason.as_deref(), keyring_key, target).await
        }
        ConsentCommands::Deny { request, reason } => {
            let verified = load(&request, keyring_key, target).await?;
            consent_approve::render(&verified);
            decide(&verified, false, reason.as_deref(), keyring_key, target).await
        }
    }
}

async fn load(
    path: &Path,
    keyring_key: &str,
    target: &VtcTarget,
) -> CliResult<VerifiedConsentRequest> {
    let approver = crate::auth::loaded_session(keyring_key)
        .ok_or_else(|| {
            format!(
                "no stored identity for this community profile. Run `{} setup` first.",
                bin_name()
            )
        })?
        .client_did;
    consent_approve::load(path, &approver, &target.did, bin_name()).await
}

async fn decide(
    req: &VerifiedConsentRequest,
    approve: bool,
    reason: Option<&str>,
    keyring_key: &str,
    target: &VtcTarget,
) -> CliResult<()> {
    let decision = req
        .decision(approve, reason)
        .map_err(|e| format!("could not build the decision: {e}"))?;
    let vtc = vtc::connect(keyring_key, target).await?;
    let response = vtc
        .client
        .decide_task_consent(&decision)
        .await
        .map_err(|e| decision_error(e, &vtc.client_did))?;
    consent_approve::report(&response);
    Ok(())
}

/// Turn the VTC's refusal into what the approver should do next.
fn decision_error(err: VtcError, approver: &str) -> Box<dyn std::error::Error> {
    let text = err.to_string();
    // The VTC answers a member's decision `permissionDenied` before it reaches
    // the approver-set check, so it means the same as `notAnApprover` here.
    let hint = if text.contains("permissionDenied") || text.contains("notAnApprover") {
        Some(format!(
            "{approver} is not an unrestricted administrator of this community, so its \
             decision does not count. Only an administrator with community-wide scope can \
             consent."
        ))
    } else {
        consent_approve::refusal_hint(&text, approver)
    };
    match hint {
        Some(hint) => format!("{text}\n  {hint}").into(),
        None => text.into(),
    }
}
