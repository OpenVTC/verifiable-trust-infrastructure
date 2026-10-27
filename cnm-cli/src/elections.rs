//! `cnm elections …` — an administrator running the community's polls, surveys and elections
//! (`vtc/elections/*`, VTI-VOT-001 – 100).
//!
//! - `create` sends a manifest (a JSON file) for the community to check, record and register
//!   with the ballot box it names. A binding election is parked for another holder of
//!   `vtc.elections.manage` and runs itself on approval.
//! - `list` and `show` read them, `close` and `cancel` end them, and `certify` asks the
//!   community to verify the ballot box's board from its own voting key and record the result.
//!
//! They travel as `cnm access` does ([`vtc_target::connect_for_tasks`]), signed with this
//! profile's own key. Members take tickets and vote through their own VTA, never through here.

use std::path::PathBuf;

use clap::Subcommand;
use serde_json::Value;
use vta_cli_common::render::{
    BOLD, DIM, GREEN, RESET, YELLOW, bin_name, is_json_output, print_json,
};
use vta_sdk::session::TransportChoice;
use vtc_client::VtcError;
use vtc_client::elections::{certify, create};

use crate::vtc::{self as vtc_target, Connected, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum ElectionsCommands {
    /// Create an election from its manifest (a JSON file, `voting/_shared` `Manifest`).
    Create {
        /// The manifest. Sent exactly as written: its digest is what every ticket and cast is
        /// bound to.
        manifest: PathBuf,
    },
    /// List the community's elections.
    List {
        /// Only elections in this state (registration, voting, closed, tallied, cancelled,
        /// pendingRegistration, registrationRefused, registered).
        #[arg(long)]
        state: Option<String>,
    },
    /// Show one election: its manifest, state, disclosure and board checkpoints.
    Show { election_id: String },
    /// Close an election early, where its manifest allows it.
    Close {
        election_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Cancel an election. Ticket issuance stops before the ballot box is asked.
    Cancel {
        election_id: String,
        #[arg(long)]
        reason: String,
    },
    /// Certify a tallied election: the community re-verifies the ballot box's whole board from
    /// its own voting key and records the result.
    Certify {
        election_id: String,
        /// An auditor's attestation (a verifiable credential, as a JSON file). Repeat for each.
        #[arg(long = "attestation")]
        attestations: Vec<PathBuf>,
    },
}

/// Run one `cnm elections` command. The session is closed on every path out.
pub async fn run(
    command: ElectionsCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_command(command, &vtc, keyring_key).await;
    vtc.client.shutdown().await;
    outcome
}

fn read_json(path: &PathBuf) -> CliResult<Value> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    Ok(serde_json::from_str(&raw).map_err(|e| format!("{} is not JSON: {e}", path.display()))?)
}

async fn run_command(command: ElectionsCommands, vtc: &Connected, keyring_key: &str) -> CliResult {
    let key = crate::access::signing_key(keyring_key)?;
    let c = &vtc.client;
    match command {
        ElectionsCommands::Create { manifest } => {
            let manifest = read_json(&manifest)?;
            let id = manifest["electionId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let box_did = manifest["ballotBox"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let created = c
                .elections_create(manifest, &key)
                .await
                .map_err(|e| refusal(vtc, e, &id, Some(&box_did)))?;
            if is_json_output() {
                return Ok(print_json(&created)?);
            }
            let state = created.state.to_string();
            println!(
                "{GREEN}created{RESET} {BOLD}{id}{RESET} — {state} (manifest {})",
                created.manifest_digest.as_str()
            );
            if state == "pendingRegistration" {
                println!(
                    "  {DIM}the ballot box has not answered yet; the community keeps delivering the \
                     registration, and no ticket is issued until it is registered{RESET}"
                );
            }
            Ok(())
        }
        ElectionsCommands::List { state } => {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let page = c
                    .elections_list(state.as_deref(), cursor.as_deref(), Some(100), &key)
                    .await
                    .map_err(|e| refusal(vtc, e, "", None))?;
                all.extend(page.elections);
                match page.next {
                    Some(n) => cursor = Some(n.to_string()),
                    None => break,
                }
            }
            if is_json_output() {
                return Ok(print_json(&all)?);
            }
            if all.is_empty() {
                println!("{DIM}no elections{RESET}");
            }
            for e in &all {
                let title = e.title.as_ref().map(|t| t.to_string()).unwrap_or_default();
                println!(
                    "{BOLD}{}{RESET}  {}  {} → {}{}  {DIM}{title}{RESET}",
                    e.election_id.as_str(),
                    e.state,
                    e.voting_opens,
                    e.voting_closes,
                    if e.binding { "  binding" } else { "" },
                );
            }
            Ok(())
        }
        ElectionsCommands::Show { election_id } => {
            let shown = c
                .elections_show(&election_id, &key)
                .await
                .map_err(|e| refusal(vtc, e, &election_id, None))?;
            if is_json_output() {
                return Ok(print_json(&shown)?);
            }
            let v = serde_json::to_value(&shown)?;
            println!(
                "{BOLD}{election_id}{RESET}  {}",
                v["state"].as_str().unwrap_or_default()
            );
            println!(
                "  manifest     {}",
                v["manifestDigest"].as_str().unwrap_or_default()
            );
            println!(
                "  ballot box   {} ({}{})",
                v["disclosure"]["ballotBox"].as_str().unwrap_or_default(),
                v["disclosure"]["ballotBoxOperator"]
                    .as_str()
                    .unwrap_or_default(),
                if v["disclosure"]["sameOperator"] == true {
                    ", run by this community's operator"
                } else {
                    ""
                }
            );
            println!(
                "  voting       {} → {}",
                v["manifest"]["votingOpens"].as_str().unwrap_or_default(),
                v["manifest"]["votingCloses"].as_str().unwrap_or_default()
            );
            if let Some(n) = v["ticketsIssued"].as_u64() {
                println!("  tickets      {n} issued");
            }
            println!(
                "  checkpoints  {}",
                v["checkpoints"].as_array().map_or(0, Vec::len)
            );
            if v.get("certified").is_some() {
                println!(
                    "  {GREEN}certified{RESET} {}",
                    v["certified"]["certifiedAt"].as_str().unwrap_or_default()
                );
            }
            Ok(())
        }
        ElectionsCommands::Close {
            election_id,
            reason,
        } => {
            let closed = c
                .elections_close(&election_id, reason.as_deref(), &key)
                .await
                .map_err(|e| refusal(vtc, e, &election_id, None))?;
            if is_json_output() {
                return Ok(print_json(&closed)?);
            }
            println!("{GREEN}closed{RESET} {election_id} — {}", closed.state);
            Ok(())
        }
        ElectionsCommands::Cancel {
            election_id,
            reason,
        } => {
            let cancelled = c
                .elections_cancel(&election_id, &reason, &key)
                .await
                .map_err(|e| refusal(vtc, e, &election_id, None))?;
            if is_json_output() {
                return Ok(print_json(&cancelled)?);
            }
            println!(
                "{GREEN}cancelled{RESET} {election_id} — {}",
                cancelled.state
            );
            Ok(())
        }
        ElectionsCommands::Certify {
            election_id,
            attestations,
        } => {
            let attestations = attestations
                .iter()
                .map(read_json)
                .collect::<CliResult<Vec<Value>>>()?;
            let certified = c
                .elections_certify(&election_id, attestations, &key)
                .await
                .map_err(|e| refusal(vtc, e, &election_id, None))?;
            if is_json_output() {
                return Ok(print_json(&certified)?);
            }
            let v = serde_json::to_value(&certified)?;
            println!(
                "{GREEN}certified{RESET} {election_id}: {} ballots counted, board of {} entries",
                v["result"]["ballotsCounted"], v["head"]["treeSize"]
            );
            for q in v["result"]["questions"].as_array().into_iter().flatten() {
                println!(
                    "  {BOLD}{}{RESET}  {}",
                    q["question"].as_str().unwrap_or_default(),
                    q
                );
            }
            Ok(())
        }
    }
}

/// The declared code a refusal carries, if it is a create's or a certify's.
fn declared_code(err: &VtcError) -> Option<&'static str> {
    let text = match err {
        VtcError::Http { body, .. } => body.as_str(),
        VtcError::Refused { document } => document.as_str(),
        VtcError::NotFound { code, .. } => code.as_str(),
        _ => return None,
    };
    create::ERROR_CODES
        .iter()
        .chain(certify::ERROR_CODES)
        .map(|d| d.code)
        .find(|c| text.contains(&format!("\"{c}\"")) || text == *c)
}

/// The fix, when a refusal names one (root CLAUDE.md, "Operator errors should suggest the fix").
fn suggested_fix(code: &str, election_id: &str, ballot_box: Option<&str>) -> Option<String> {
    let bin = bin_name();
    Some(match code {
        c if c == create::error_codes::BALLOT_BOX_NOT_TRUSTED.code => format!(
            "{} is not one of this community's trusted voting services. A host operator adds it \
             to the VTC's config.toml and restarts the VTC:\n\n  [[voting.trusted_ballot_boxes]]\n  \
             did = \"{}\"\n  operator = \"<who runs it>\"\n  same_operator = false",
            ballot_box.unwrap_or("the ballot box"),
            ballot_box.unwrap_or("<its DID>")
        ),
        c if c == create::error_codes::ELECTION_EXISTS.code => format!(
            "this community already holds an election called {election_id}. Pick another \
             electionId, or see it with:\n  {bin} elections show {election_id}"
        ),
        c if c == certify::error_codes::NOT_TALLIED.code => format!(
            "the ballot box has not published a final result yet. Check where it stands with:\n  \
             {bin} elections show {election_id}"
        ),
        _ => return None,
    })
}

fn refusal(
    vtc: &Connected,
    err: VtcError,
    election_id: &str,
    ballot_box: Option<&str>,
) -> Box<dyn std::error::Error> {
    if let VtcError::Parked { action_id, message } = &err {
        return format!(
            "{message}\n  A binding election takes another administrator's consent. Nothing more \
             to send: it is created when the approval lands. Follow it with `{bin} actions show \
             {action_id}`.",
            bin = bin_name()
        )
        .into();
    }
    let text = err.to_string();
    if let Some(fix) = declared_code(&err).and_then(|c| suggested_fix(c, election_id, ballot_box)) {
        return format!("{fix}\n({text})").into();
    }
    if text.contains("stepUpRequest") || text.contains("passkey gesture") {
        return format!(
            "{YELLOW}the VTC needs a passkey gesture from {} first{RESET}: approve it in the admin \
             console, then run the same command again.\n({text})",
            vtc.client_did
        )
        .into();
    }
    format!("the VTC refused {}: {text}", vtc.client_did).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(code: &str) -> VtcError {
        VtcError::Refused {
            document: serde_json::json!({ "payload": { "code": code, "message": "no" } })
                .to_string(),
        }
    }

    #[test]
    fn an_untrusted_ballot_box_prints_the_config_to_add() {
        let code =
            declared_code(&refused(create::error_codes::BALLOT_BOX_NOT_TRUSTED.code)).unwrap();
        let fix = suggested_fix(code, "agm", Some("did:web:ballots.example")).unwrap();
        assert!(fix.contains("[[voting.trusted_ballot_boxes]]"), "{fix}");
        assert!(fix.contains("did = \"did:web:ballots.example\""), "{fix}");
    }

    #[test]
    fn a_taken_identifier_points_at_the_election() {
        let code = declared_code(&refused(create::error_codes::ELECTION_EXISTS.code)).unwrap();
        assert!(
            suggested_fix(code, "agm", None)
                .unwrap()
                .contains("elections show agm")
        );
    }
}
