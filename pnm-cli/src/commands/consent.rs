//! `pnm consent {show,approve,deny}` — answer this VTA's consent requests.
//!
//! A task under a `requires: consent` rule (`pnm approvals require … --consent`)
//! is deferred until the named approver set agrees. The VTA pushes a signed
//! `task-consent/request/0.1` to each approver and hands the same documents
//! back to the requester in its refusal (`details.consentRequests`). An approver
//! whose `pnm` profile is in the set takes the relayed request and answers it
//! here; the decision is this profile's signed `task-consent/decision/0.1`.
//! What is shown and the code comparison approval requires are shared with
//! `cnm consent` ([`vta_cli_common::consent_approve`]).

use std::path::Path;

use vta_cli_common::consent_approve;
use vta_sdk::prelude::*;
use vta_sdk::task_consent::{DECISION_TYPE, VerifiedConsentRequest, decision};

use crate::cli::ConsentCommands;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// How long to wait for the VTA to answer a decision.
const DECISION_TIMEOUT_SECS: u64 = 30;

pub(crate) async fn run(
    client: &VtaClient,
    keyring_key: &str,
    vta_did: Option<&str>,
    command: ConsentCommands,
) -> CliResult<()> {
    match command {
        ConsentCommands::Show { request } => {
            let (verified, _) = load(&request, client, keyring_key, vta_did).await?;
            consent_approve::render(&verified);
            Ok(())
        }
        ConsentCommands::Approve {
            request,
            match_code,
            reason,
        } => {
            let (verified, approver) = load(&request, client, keyring_key, vta_did).await?;
            consent_approve::render(&verified);
            consent_approve::confirm_match_code(&verified, match_code.as_deref(), "pnm")?;
            decide(client, &verified, true, reason.as_deref(), &approver).await
        }
        ConsentCommands::Deny { request, reason } => {
            let (verified, approver) = load(&request, client, keyring_key, vta_did).await?;
            consent_approve::render(&verified);
            decide(client, &verified, false, reason.as_deref(), &approver).await
        }
    }
}

/// Verify the request addressed to this profile, as issued by this VTA.
async fn load(
    path: &Path,
    client: &VtaClient,
    keyring_key: &str,
    vta_did: Option<&str>,
) -> CliResult<(VerifiedConsentRequest, String)> {
    let approver = crate::auth::loaded_session(keyring_key)
        .ok_or("no PNM session — run `pnm setup` first")?
        .client_did;
    // The configured DID first: a REST client is never told the VTA's DID.
    let vta_did = vta_did.or(client.vta_did()).ok_or(
        "this VTA's DID is not known, so the request's issuer cannot be checked. Record it \
         with `pnm setup continue <slug> --vta-did <did>`, or connect over DIDComm or TSP.",
    )?;
    let verified = consent_approve::load(path, &approver, vta_did, "pnm").await?;
    Ok((verified, approver))
}

async fn decide(
    client: &VtaClient,
    req: &VerifiedConsentRequest,
    approve: bool,
    reason: Option<&str>,
    approver: &str,
) -> CliResult<()> {
    let payload = serde_json::to_value(
        req.decision(approve, reason)
            .map_err(|e| format!("could not build the decision: {e}"))?,
    )?;
    // The client signs every document it sends with this profile's key, which
    // is the approver's authority: the VTA takes the signer from the proof.
    let reply = client
        .dispatch_trust_task(DECISION_TYPE, payload, DECISION_TIMEOUT_SECS)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> {
            let text = e.to_string();
            match consent_approve::refusal_hint(&text, approver) {
                Some(hint) => format!("{text}\n  {hint}").into(),
                None => text.into(),
            }
        })?;
    let response: decision::Response = serde_json::from_value(reply)
        .map_err(|e| format!("the VTA's answer has an unexpected shape: {e}"))?;
    consent_approve::report(&response);
    Ok(())
}
