//! `cnm elections …` — an administrator running the community's polls, surveys and elections
//! (`vtc/elections/*`, VTI-VOT-001 – 100).
//!
//! - `create` sends a manifest (a JSON file) for the community to check, record and register
//!   with the ballot box it names. A binding election is parked for another holder of
//!   `vtc.elections.manage` and runs itself on approval.
//! - `ballot-boxes` lists the voting services the community trusts, which a manifest's
//!   `ballotBox` must name.
//! - `list` and `show` read them, `close` and `cancel` end them, and `certify` asks the
//!   community to verify the ballot box's board from its own voting key and record the result.
//!
//! - `manifest init` writes a starting manifest and `manifest check` checks one, both offline:
//!   `check` validates it against the pinned `vtc/elections/create` schema and runs
//!   [`vti_voting::rules::check_new_manifest`] — the checks the community runs that need nothing
//!   but the manifest and the clock — plus that it names this community. What only the community
//!   knows (its trusted ballot boxes, the identifiers it has used) is checked on `create`.
//!
//! The rest travel as `cnm access` does ([`vtc_target::connect_for_tasks`]), signed with this
//! profile's own key. Members take tickets and vote through their own VTA, never through here.

use std::path::PathBuf;

use chrono::{DateTime, Duration, DurationRound, Utc};
use clap::Subcommand;
use serde_json::{Value, json};
use trust_tasks_rs::validate::ValidatedPayload;
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
    /// Write or check a manifest, offline: nothing is sent.
    Manifest {
        #[command(subcommand)]
        command: ManifestCommands,
    },
    /// Create an election from its manifest (a JSON file, `voting/_shared` `Manifest`).
    Create {
        /// The manifest. Sent exactly as written: its digest is what every ticket and cast is
        /// bound to.
        manifest: PathBuf,
    },
    /// List the voting services this community trusts: a manifest's `ballotBox` names one.
    BallotBoxes,
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

#[derive(Subcommand)]
pub enum ManifestCommands {
    /// Write a starting manifest for this community: one yes/no question, open voting by its
    /// members for a week from tomorrow. Edit it, `check` it, then `create` it.
    Init {
        /// The voting service that will hold the board: one of this community's trusted
        /// ballot boxes (`[voting] trusted_ballot_boxes` in the VTC's configuration).
        #[arg(long)]
        ballot_box: String,
        /// The election's identifier (letters, digits, `.`, `-`, `_`). Default: `poll-<today>`.
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        title: Option<String>,
        /// Where to write it. Default: standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Replace `--out` if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Check a manifest as the community will: its schema, the rules between its fields, that
    /// voting has not closed, and that it names this community. Prints its digest.
    Check { manifest: PathBuf },
}

/// A starting manifest: one yes/no question, tickets from `now`, voting for a week from a day
/// after the next whole hour.
pub fn starter_manifest(
    community: &str,
    ballot_box: &str,
    id: Option<&str>,
    title: Option<&str>,
    now: DateTime<Utc>,
) -> Value {
    let rfc3339 = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let next_hour = now.duration_trunc(Duration::hours(1)).unwrap_or(now) + Duration::hours(1);
    let opens = next_hour + Duration::days(1);
    let mut m = json!({
        "electionId": id.map_or_else(|| format!("poll-{}", now.format("%Y-%m-%d")), str::to_string),
        "community": community,
        "questions": [{
            "key": "q1",
            "type": "choice",
            "text": "",
            "options": [{ "key": "yes", "label": "Yes" }, { "key": "no", "label": "No" }],
            "minSelections": 1,
            "maxSelections": 1,
            "optional": true
        }],
        "secrecy": "open",
        "roll": { "rule": "members" },
        "registrationOpensAt": rfc3339(now),
        "votingOpensAt": rfc3339(opens),
        "votingClosesAt": rfc3339(opens + Duration::days(7)),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] },
        "ballotBox": ballot_box,
        "binding": false,
        "allowEarlyClose": false,
        "resultsBeforeClose": false,
        "textReleaseThreshold": 10
    });
    if let Some(t) = title {
        m["title"] = json!(t);
    }
    m
}

/// The warning an administrator is given for a manifest that releases written answers after
/// fewer than 10 counted ballots (VTI-VOT-065: at least 1, and SHOULD be at least 10); `None`
/// at 10 or more. Members are told the same before they take a ticket (VTI-VOT-090).
#[must_use]
pub fn low_text_release(manifest: &Value) -> Option<String> {
    let t = manifest["textReleaseThreshold"].as_u64()?;
    (t < 10).then(|| {
        format!(
            "textReleaseThreshold is {t}: below 10, a written answer may identify who wrote it — \
             members are told this before they take a ticket. Use only where that is acceptable."
        )
    })
}

/// What `manifest check` finds: the digest of a manifest that passes, or the first problem.
///
/// # Errors
/// The first problem, as the community would name it.
pub fn check_manifest_offline(
    manifest: &Value,
    community: &str,
    now: DateTime<Utc>,
) -> Result<String, String> {
    create::Payload::validate_value(&json!({ "manifest": manifest }))
        .map_err(|e| format!("out of schema (vtc/elections/create/0.4): {e}"))?;
    let m = vti_voting::rules::check_new_manifest(manifest, now).map_err(|e| e.to_string())?;
    if m.community.as_str() != community {
        return Err(format!(
            "community is {}, not this community ({community}): a community creates only its own \
             elections",
            m.community.as_str()
        ));
    }
    let digest = vti_voting::rules::manifest_digest(manifest).map_err(|e| e.to_string())?;
    Ok(vti_voting::rules::digest_multibase(&digest))
}

/// Run a `cnm elections manifest` command for the community whose DID is `community`. Offline:
/// nothing is sent and no session is opened.
pub fn run_manifest(command: ManifestCommands, community: &str) -> CliResult {
    let bin = bin_name();
    match command {
        ManifestCommands::Init {
            ballot_box,
            id,
            title,
            out,
            force,
        } => {
            let m = starter_manifest(
                community,
                &ballot_box,
                id.as_deref(),
                title.as_deref(),
                Utc::now(),
            );
            let text = format!("{}\n", serde_json::to_string_pretty(&m)?);
            let Some(path) = out else {
                print!("{text}");
                return Ok(());
            };
            if path.exists() && !force {
                return Err(format!(
                    "{} exists. Pass --force to replace it, or choose another --out.",
                    path.display()
                )
                .into());
            }
            std::fs::write(&path, text)
                .map_err(|e| format!("could not write {}: {e}", path.display()))?;
            if is_json_output() {
                return Ok(print_json(
                    &json!({ "written": path.display().to_string() }),
                )?);
            }
            println!("{GREEN}wrote{RESET} {}", path.display());
            println!(
                "  {DIM}set the question, the schedule and who votes; then{RESET}\n  \
                 {bin} elections manifest check {p}\n  {bin} elections create {p}",
                p = path.display()
            );
            Ok(())
        }
        ManifestCommands::Check { manifest } => {
            let m = read_json(&manifest)?;
            let outcome = check_manifest_offline(&m, community, Utc::now());
            if is_json_output() {
                print_json(&match &outcome {
                    Ok(digest) => json!({ "ok": true, "manifestDigest": digest }),
                    Err(problem) => json!({ "ok": false, "problem": problem }),
                })?;
                return outcome.map(|_| ()).map_err(Into::into);
            }
            match outcome {
                Ok(digest) => {
                    println!(
                        "{GREEN}ok{RESET} {BOLD}{}{RESET} — manifest {digest}",
                        m["electionId"].as_str().unwrap_or_default()
                    );
                    if let Some(warning) = low_text_release(&m) {
                        println!("  {YELLOW}{warning}{RESET}");
                    }
                    println!(
                        "  {DIM}on create the community also checks that the ballot box is one it \
                         trusts and that the identifier is unused{RESET}"
                    );
                    Ok(())
                }
                Err(problem) => {
                    Err(format!("{} does not pass: {problem}", manifest.display()).into())
                }
            }
        }
    }
}

/// Run one `cnm elections` command. The session is closed on every path out; `manifest`
/// opens none.
pub async fn run(
    command: ElectionsCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    if let ElectionsCommands::Manifest { command } = command {
        return run_manifest(command, &target.did);
    }
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
        ElectionsCommands::Manifest { .. } => {
            unreachable!("`manifest` is answered in `run`, before a session is opened")
        }
        ElectionsCommands::Create { manifest } => {
            let manifest = read_json(&manifest)?;
            // vtc/elections/create/0.4: a composing client SHOULD warn below 10 (VTI-VOT-065).
            if !is_json_output()
                && let Some(warning) = low_text_release(&manifest)
            {
                eprintln!("{YELLOW}{warning}{RESET}");
            }
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
        ElectionsCommands::BallotBoxes => {
            let listed = c
                .elections_ballot_boxes(&key)
                .await
                .map_err(|e| refusal(vtc, e, "", None))?;
            if is_json_output() {
                return Ok(print_json(&listed)?);
            }
            if listed.ballot_boxes.is_empty() {
                println!(
                    "{DIM}no trusted ballot boxes: the host operator adds one under \
                     [voting] trusted_ballot_boxes{RESET}"
                );
            }
            for b in &listed.ballot_boxes {
                let same = if b.same_operator {
                    format!("  {YELLOW}also runs this community{RESET}")
                } else {
                    String::new()
                };
                println!(
                    "{BOLD}{}{RESET}  {}{same}",
                    b.did.as_str(),
                    b.operator.as_str()
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
                match page.next_cursor {
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
                    e.voting_opens_at,
                    e.voting_closes_at,
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
                v["manifest"]["votingOpensAt"].as_str().unwrap_or_default(),
                v["manifest"]["votingClosesAt"].as_str().unwrap_or_default()
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
             did = \"{}\"\n  operator = \"<who runs it>\"\n  same_operator = false\n\n\
             Or name one it already trusts, listed by:\n\n  {bin} elections ballot-boxes",
            ballot_box.unwrap_or("the ballot box"),
            ballot_box.unwrap_or("<its DID>")
        ),
        c if c == create::error_codes::ELECTION_EXISTS.code => format!(
            "this community already holds an election called {election_id}. Pick another \
             electionId, or see it with:\n  {bin} elections show {election_id}"
        ),
        c if c == create::error_codes::INVALID_MANIFEST.code => format!(
            "the manifest breaks the rule named below. Check it offline until it passes, then \
             create it again:\n  {bin} elections manifest check <manifest.json>"
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

    const COMMUNITY: &str = "did:webvh:QmCommunity:community.example";
    const BOX: &str = "did:webvh:QmBallots:votes.example.net";

    fn now() -> DateTime<Utc> {
        "2027-03-04T10:20:30Z".parse().unwrap()
    }

    #[test]
    fn the_starter_manifest_passes_as_written() {
        let m = starter_manifest(COMMUNITY, BOX, Some("agm-2027"), Some("AGM"), now());
        assert_eq!(m["electionId"], "agm-2027");
        assert_eq!(m["title"], "AGM");
        assert_eq!(m["registrationOpensAt"], "2027-03-04T10:20:30Z");
        assert_eq!(m["votingOpensAt"], "2027-03-05T11:00:00Z");
        assert_eq!(m["votingClosesAt"], "2027-03-12T11:00:00Z");
        let digest = check_manifest_offline(&m, COMMUNITY, now()).unwrap();
        assert!(digest.starts_with('z'), "{digest}");
        let defaulted = starter_manifest(COMMUNITY, BOX, None, None, now());
        assert_eq!(defaulted["electionId"], "poll-2027-03-04");
        assert!(defaulted.get("title").is_none());
    }

    /// VTI-VOT-065: 1 – 9 passes the check, with a warning; 10 does not warn.
    #[test]
    fn vti_vot_065_a_threshold_below_ten_passes_with_a_warning() {
        let mut m = starter_manifest(COMMUNITY, BOX, None, None, now());
        assert_eq!(low_text_release(&m), None);
        m["textReleaseThreshold"] = json!(1);
        check_manifest_offline(&m, COMMUNITY, now()).expect("1 is a valid threshold");
        let w = low_text_release(&m).unwrap();
        assert!(w.contains("may identify who wrote it"), "{w}");
        m["textReleaseThreshold"] = json!(0);
        assert!(check_manifest_offline(&m, COMMUNITY, now()).is_err());
    }

    #[test]
    fn check_names_what_the_community_would_refuse() {
        let m = starter_manifest(COMMUNITY, BOX, None, None, now());

        let mut out_of_schema = m.clone();
        out_of_schema["secrecy"] = json!("secret");
        let e = check_manifest_offline(&out_of_schema, COMMUNITY, now()).unwrap_err();
        assert!(e.starts_with("out of schema"), "{e}");

        let mut bounds = m.clone();
        bounds["questions"][0]["maxSelections"] = json!(3);
        let e = check_manifest_offline(&bounds, COMMUNITY, now()).unwrap_err();
        assert!(
            e.contains("minSelections <= maxSelections <= options"),
            "{e}"
        );

        let later = now() + Duration::days(30);
        let e = check_manifest_offline(&m, COMMUNITY, later).unwrap_err();
        assert!(e.contains("votingClosesAt is already past"), "{e}");

        let e = check_manifest_offline(&m, "did:web:other.example", now()).unwrap_err();
        assert!(e.contains("not this community"), "{e}");
    }

    #[test]
    fn check_and_the_community_agree_on_the_digest() {
        let m = starter_manifest(COMMUNITY, BOX, None, None, now());
        let expected =
            vti_voting::rules::digest_multibase(&vti_voting::rules::manifest_digest(&m).unwrap());
        assert_eq!(
            check_manifest_offline(&m, COMMUNITY, now()).unwrap(),
            expected
        );
    }

    #[test]
    fn an_invalid_manifest_points_at_the_offline_check() {
        let code = declared_code(&refused(create::error_codes::INVALID_MANIFEST.code)).unwrap();
        assert!(
            suggested_fix(code, "agm", None)
                .unwrap()
                .contains("elections manifest check")
        );
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
