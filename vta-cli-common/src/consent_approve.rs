//! The approver's side of task consent, shared by `pnm consent` (a VTA's
//! requests) and `cnm consent` (a VTC's).
//!
//! A node raises a signed `task-consent/request/0.1` for each approver, pushes
//! it, and hands the same documents back to the requester in its refusal
//! (`details.consentRequests`). An approver with no device enrolled for the
//! push takes the relayed copy and answers it here. Verification, the match
//! code and the decision payload come from [`vta_sdk::task_consent`]; this
//! module is the operator-facing half both CLIs present identically: reading
//! the input, what is shown, and the code comparison approval requires.
//!
//! That comparison is the whole security value of the ceremony. The code is
//! derived from the digest the decision binds to, so matching screens mean the
//! change being approved is the change that will run. Denying needs no code: a
//! refusal cannot be abused.

use std::io::{IsTerminal, Read};
use std::path::Path;

use serde_json::Value;
use vta_sdk::task_consent::{
    ConsentRequest, VerifiedConsentRequest, decision::Response, decision::ResponseStatus,
    extract_requests,
};

use crate::render::{BOLD, DIM, GREEN, RED, RESET, YELLOW};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Read `path` (`-` for stdin), pick the request addressed to `approver`, and
/// verify it as issued by `expected_issuer`.
///
/// `bin` names the CLI in guidance, e.g. `pnm`.
pub async fn load(
    path: &Path,
    approver: &str,
    expected_issuer: &str,
    bin: &str,
) -> CliResult<VerifiedConsentRequest> {
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
                    pushed to the approvers' devices instead."
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
        .find(|r| r.recipient() == Some(approver))
        .ok_or_else(|| {
            format!(
                "none of these requests is addressed to this profile ({approver}). They are \
                 for: {}. Each approver answers the request addressed to them; switch to \
                 that approver's {bin} profile, or ask the requester to relay yours.",
                recipients.join(", ")
            )
        })?;

    let resolver = vta_sdk::resolver::shared_did_resolver_from_env()
        .await
        .map_err(|e| format!("could not start a DID resolver: {e}"))?;
    let resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::new(resolver);
    Ok(mine
        .verify(expected_issuer, approver, &resolver, chrono::Utc::now())
        .await
        .map_err(|e| format!("refusing this request: {e}"))?)
}

/// Show what the request asks, and the code to compare.
pub fn render(req: &VerifiedConsentRequest) {
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

/// Approval proceeds only on a code the operator compared: `given`, or typed
/// at the terminal.
pub fn confirm_match_code(
    req: &VerifiedConsentRequest,
    given: Option<&str>,
    bin: &str,
) -> CliResult<()> {
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
             approve. Deny it with `{bin} consent deny` if you do not recognise it."
        )
        .into());
    }
    Ok(())
}

/// Report the node's answer to a decision.
pub fn report(response: &Response) {
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
        other => println!("the node answered `{other}`"),
    }
}

/// What the approver should do next, for a refusal naming one of the
/// decision's declared codes. `None` when the error names none of them.
pub fn refusal_hint(error_text: &str, approver: &str) -> Option<String> {
    if error_text.contains("noPending") {
        Some(
            "no pending request matches: it was already decided, it lapsed (requests last \
             15 minutes), or it was never raised. Ask the requester to submit the operation \
             again and relay the new request."
                .into(),
        )
    } else if error_text.contains("challengeMismatch") {
        Some(
            "this request has been superseded by a newer one for the same change. Ask the \
             requester to relay the current request."
                .into(),
        )
    } else if error_text.contains("requesterExcluded") {
        Some(
            "you asked for this change, and the requester cannot consent to their own \
             request. Another approver has to answer it."
                .into(),
        )
    } else if error_text.contains("notAnApprover") {
        Some(format!(
            "{approver} is not in the approver set this request names, so its decision does \
             not count."
        ))
    } else {
        None
    }
}
