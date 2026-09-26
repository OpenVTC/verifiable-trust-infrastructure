//! `cnm consent {show,approve,deny}` — answer the community's consent requests.
//!
//! Making or widening an unrestricted administrator needs another unrestricted
//! administrator's consent (VTI-APV-014). The VTC raises a signed
//! `task-consent/request/0.1` for each approver, pushes it to them, and hands
//! the same documents back to the requester in its refusal
//! (`details.consentRequests`). Until this command, answering took a device
//! enrolled to handle the push; now an approver with a `cnm` profile can take
//! the relayed request and sign the decision here.
//!
//! The request is verified before anything is shown: the VTC must have signed
//! it, it must be addressed to this profile's DID, and it must not have
//! expired. Approving then requires the operator to **type the match code the
//! requester sees** (or pass `--match-code`). That comparison is the whole
//! security value of the ceremony — the code is derived from the digest the
//! decision binds to, so matching screens mean the change being approved is the
//! change that will run. Denying needs no code: a refusal cannot be abused.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::Value;
use vta_cli_common::render::{BOLD, DIM, GREEN, RED, RESET, YELLOW, bin_name};
use vta_sdk::task_consent::{ConsentRequest, VerifiedConsentRequest, extract_requests};
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
            render(&verified);
            Ok(())
        }
        ConsentCommands::Approve {
            request,
            match_code,
            reason,
        } => {
            let verified = load(&request, keyring_key, target).await?;
            render(&verified);
            confirm_match_code(&verified, match_code.as_deref())?;
            decide(&verified, true, reason.as_deref(), keyring_key, target).await
        }
        ConsentCommands::Deny { request, reason } => {
            let verified = load(&request, keyring_key, target).await?;
            render(&verified);
            decide(&verified, false, reason.as_deref(), keyring_key, target).await
        }
    }
}

/// Read the input, pick the request addressed to this profile, and verify it.
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

    let text = if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?
    };
    let input: Value =
        serde_json::from_str(&text).map_err(|e| format!("the input is not JSON: {e}"))?;

    let requests = extract_requests(&input);
    if requests.is_empty() {
        return Err(
            "no task-consent request in the input. Pass the request document, or the \
                    requester's refusal (its `details.consentRequests`). If the refusal says \
                    `consentRequestsOmitted`, the requests were too large to relay: they were \
                    pushed to your device instead."
                .into(),
        );
    }
    let recipients: Vec<String> = requests
        .iter()
        .filter_map(|r| r.get("recipient").and_then(Value::as_str).map(String::from))
        .collect();
    let mine = requests
        .into_iter()
        .map(ConsentRequest::new)
        .find(|r| r.recipient() == Some(approver.as_str()))
        .ok_or_else(|| {
            format!(
                "none of these requests is addressed to this profile ({approver}). They are \
                 for: {}. Each approver answers the request addressed to them; switch \
                 profile with `--community`, or ask the requester to relay yours.",
                recipients.join(", ")
            )
        })?;

    let resolver = vta_sdk::resolver::shared_did_resolver_from_env()
        .await
        .map_err(|e| format!("could not start a DID resolver: {e}"))?;
    let resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::new(resolver);
    Ok(mine
        .verify(&target.did, &approver, &resolver, chrono::Utc::now())
        .await
        .map_err(|e| format!("refusing this request: {e}"))?)
}

fn render(req: &VerifiedConsentRequest) {
    let p = req.payload();
    println!();
    println!("  {BOLD}Consent requested by {}{RESET}", req.issuer());
    println!("  {DIM}requester:{RESET} {}", p.requester);
    if let Some(subject) = &p.subject {
        println!("  {DIM}subject:  {RESET} {subject}");
    }
    println!("  {DIM}task:     {RESET} {}", p.task_type);
    if !p.effects.is_empty() {
        println!("  {DIM}effects:{RESET}");
        for effect in &p.effects {
            println!("    - {}", *effect.summary);
        }
    }
    for consequence in &p.consequences {
        println!("  {YELLOW}! {}{RESET}", **consequence);
    }
    println!(
        "  {DIM}needs:    {RESET} {} approval(s) from `{}`{}",
        p.min_approvals,
        p.approver_set,
        if p.exclude_requester {
            ", not the requester"
        } else {
            ""
        }
    );
    println!("  {DIM}expires:  {RESET} {}", p.expires_at.to_rfc3339());
    println!();
    println!("      {BOLD}code: {}{RESET}", req.match_code());
    println!();
}

/// Approval proceeds only on a code the operator compared.
fn confirm_match_code(req: &VerifiedConsentRequest, given: Option<&str>) -> CliResult<()> {
    let typed = match given {
        Some(code) => code.to_string(),
        None if std::io::stderr().is_terminal() => dialoguer::Input::<String>::new()
            .with_prompt("Type the code shown on the requester's screen")
            .interact_text()?,
        None => {
            return Err(
                "approving needs the requester's match code: pass `--match-code <code>` \
                 after comparing it with the code above"
                    .into(),
            );
        }
    };
    if !typed.trim().eq_ignore_ascii_case(req.match_code()) {
        return Err(format!(
            "{RED}the code does not match{RESET} — nothing was approved. A different code \
             means the change the requester sees is not the change this request would \
             approve. Deny it with `{} consent deny` if you do not recognise it.",
            bin_name()
        )
        .into());
    }
    Ok(())
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

    use vta_sdk::task_consent::decision::ResponseStatus;
    match response.status {
        ResponseStatus::Granted => println!(
            "{GREEN}✓ consent granted{RESET} — the requester can now submit the operation again."
        ),
        ResponseStatus::Pending => println!(
            "{GREEN}✓ approval recorded{RESET} — {} of {} so far; another approver must \
             still answer.",
            response.approvals.unwrap_or(0),
            response
                .needed
                .map(|n| n.get().to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        ResponseStatus::Denied => {
            println!("{YELLOW}✗ request denied{RESET} — the requester has to ask again.")
        }
        other => println!("the VTC answered `{other}`"),
    }
    Ok(())
}

/// Turn the VTC's refusal into what the approver should do next.
fn decision_error(err: VtcError, approver: &str) -> Box<dyn std::error::Error> {
    let text = err.to_string();
    let hint = if text.contains("noPending") {
        "the VTC holds no pending request for this code: it was already decided, it \
         lapsed (requests last 15 minutes), or it was never raised. Ask the requester to \
         submit the operation again and relay the new request."
            .to_string()
    } else if text.contains("challengeMismatch") {
        "this request has been superseded by a newer one for the same change. Ask the \
         requester to relay the current request."
            .to_string()
    } else if text.contains("requesterExcluded") {
        "you asked for this change, and the requester cannot consent to their own request. \
         Another unrestricted administrator has to approve it."
            .to_string()
    } else if text.contains("notAnApprover") || text.contains("permissionDenied") {
        format!(
            "{approver} is not an unrestricted administrator of this community, so its \
             decision does not count. Only an administrator with community-wide scope can \
             consent."
        )
    } else {
        return text.into();
    };
    format!("{text}\n  {hint}").into()
}
